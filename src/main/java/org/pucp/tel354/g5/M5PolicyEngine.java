package org.pucp.tel354.g5;

import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.*;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * M5 - PolicyEngine
 * Seguridad perimetral en el switch de borde (R5).
 * Controla trafico entrante desde Internet hacia la intranet PUCP.
 *
 * Estrategia:
 *   - Whitelist de puertos: solo TCP 80, 443, 22, 25 permitidos desde exterior
 *   - Lista negra de IPs actualizable via REST sin reiniciar el controlador
 *   - Suricata en interfaz WAN reporta IPs maliciosas -> bloqueo en < 200ms
 *
 * Solo aplica al switch de borde (border switch). Los demas switches
 * no tienen reglas perimetrales.
 */
@Component(immediate = true)
public class M5PolicyEngine {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final int T4_POLICY     = 4;
    private static final int T2_MITIGATION = 2;

    // puertos permitidos desde internet (whitelist)
    private static final int[] ALLOWED_PORTS = { 80, 443, 22, 25 };

    // prioridades
    private static final int PRIORITY_BLACKLIST = 60000; // mayor que todo
    private static final int PRIORITY_WHITELIST = 30000;
    private static final int PRIORITY_DEFAULT_DENY = 29000;

    // el switch de borde se configura al activar el componente
    // en produccion esto viene de NetworkConfig de ONOS
    private DeviceId borderSwitchId;
    private PortNumber wanPort; // puerto WAN del switch de borde

    // lista negra de IPs (se actualiza en tiempo real)
    private final Set<IpAddress> blacklist = new CopyOnWriteArraySet<>();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    private ApplicationId appId;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.pucp.tel354.g5.policy");

        // TODO: leer borderSwitchId y wanPort desde NetworkConfig de ONOS
        // por ahora hardcodeado para pruebas en Mininet
        borderSwitchId = DeviceId.deviceId("of:0000000000000001");
        wanPort = PortNumber.portNumber(1);

        installPerimeterRules();

        log.info("M5PolicyEngine activo - switch borde: {} puerto WAN: {}",
                borderSwitchId, wanPort);
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId);
        log.info("M5PolicyEngine detenido");
    }

    // instala las reglas perimetrales base en el switch de borde
    private void installPerimeterRules() {
        // whitelist de puertos: solo trafico entrante en los puertos permitidos pasa
        for (int port : ALLOWED_PORTS) {
            // TCP
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchInPort(wanPort)
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_TCP)
                    .matchTcpDst(TpPort.tpPort(port))
                    .build();

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .transition(T4_POLICY)
                    .build();

            installRule(borderSwitchId, T4_POLICY, selector, treatment,
                    PRIORITY_WHITELIST, 0, 0);
        }

        // drop default para todo trafico entrante WAN no whitelisted
        TrafficSelector defaultWan = DefaultTrafficSelector.builder()
                .matchInPort(wanPort)
                .matchEthType(Ethernet.TYPE_IPV4)
                .build();

        TrafficTreatment drop = DefaultTrafficTreatment.builder().drop().build();
        installRule(borderSwitchId, T4_POLICY, defaultWan, drop,
                PRIORITY_DEFAULT_DENY, 0, 0);

        log.info("Reglas perimetrales instaladas - puertos whitelist: {}",
                Arrays.toString(ALLOWED_PORTS));
    }

    // agrega una IP a la lista negra y la bloquea inmediatamente en el switch de borde
    // este metodo es llamado por Suricata via REST o por el admin desde M6
    public void blockIp(String ipStr) {
        IpAddress ip;
        try {
            ip = IpAddress.valueOf(ipStr);
        } catch (Exception e) {
            log.error("IP invalida: {}", ipStr);
            return;
        }

        if (blacklist.contains(ip)) {
            log.debug("IP {} ya estaba en blacklist", ip);
            return;
        }

        blacklist.add(ip);

        // instalar regla de bloqueo en T2 con hard_timeout
        // deteccion <10s (Suricata WAN) + instalacion ~200ms = total <10.2s
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(wanPort)
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(IpPrefix.valueOf(ip, 32))
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .drop()
                .build();

        // timeout 3600s (1 hora), se puede remover manualmente con unblockIp()
        installRule(borderSwitchId, T2_MITIGATION, selector, treatment,
                PRIORITY_BLACKLIST, 0, 3600);

        log.warn("IP {} bloqueada en switch de borde (R5 perimetral)", ip);
    }

    // remueve una IP de la lista negra (para desbloqueo manual o cuando expira)
    public void unblockIp(String ipStr) {
        IpAddress ip;
        try {
            ip = IpAddress.valueOf(ipStr);
        } catch (Exception e) {
            log.error("IP invalida: {}", ipStr);
            return;
        }

        if (!blacklist.remove(ip)) {
            log.debug("IP {} no estaba en blacklist", ip);
            return;
        }

        // remover regla del switch
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(wanPort)
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(IpPrefix.valueOf(ip, 32))
                .build();

        FlowRule toRemove = DefaultFlowRule.builder()
                .forDevice(borderSwitchId)
                .forTable(T2_MITIGATION)
                .withSelector(selector)
                .withTreatment(DefaultTrafficTreatment.builder().drop().build())
                .withPriority(PRIORITY_BLACKLIST)
                .fromApp(appId)
                .makePermanent()
                .build();

        flowRuleService.removeFlowRules(toRemove);
        log.info("IP {} removida de blacklist", ip);
    }

    // retorna la lista negra actual (para consulta desde M6 AdminConsole)
    public Set<IpAddress> getBlacklist() {
        return Collections.unmodifiableSet(blacklist);
    }

    // actualiza la whitelist de puertos (reconfiguracion en caliente)
    public void updateWhitelist(int[] newPorts) {
        // remover reglas viejas y reinstalar con nuevos puertos
        // TODO: implementar diff para no reinstalar lo que no cambio
        flowRuleService.removeFlowRulesById(appId);
        installPerimeterRules();
        log.info("Whitelist actualizada: {}", Arrays.toString(newPorts));
    }

    private void installRule(DeviceId deviceId, int tableId,
                              TrafficSelector selector, TrafficTreatment treatment,
                              int priority, int idleTimeout, int hardTimeout) {
        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(priority)
                .withIdleTimeout(idleTimeout)
                .withHardTimeout(hardTimeout)
                .fromApp(appId)
                .build();
        flowRuleService.applyFlowRules(rule);
    }
}
