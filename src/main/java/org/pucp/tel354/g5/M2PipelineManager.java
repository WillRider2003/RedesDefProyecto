package org.pucp.tel354.g5;

import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.device.*;
import org.onosproject.net.flow.*;
import org.onosproject.net.host.HostService;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * M2 - PipelineManager
 * Construye y mantiene el pipeline T0-T5 en los switches OpenFlow del campus.
 *
 * Tablas:
 *   T0 - Ingreso       : captura EAPOL/ARP/DHCP, drop default
 *   T1 - Anti-spoofing : valida MAC+IP contra registro DHCP
 *   T2 - Mitigacion    : reglas de bloqueo instaladas por M4 (con timeouts)
 *   T3 - Identidad     : MAC -> VLAN + metadata(rol), instalado por M1
 *   T4 - Politica      : reglas por rol segun metadata de T3
 *   T5 - Reenvio       : output por puerto o flood
 */
@Component(immediate = true)
public class M2PipelineManager {

    private final Logger log = LoggerFactory.getLogger(getClass());

    // indices de tablas
    static final int T0_INGRESS    = 0;
    static final int T1_ANTISPOOFING = 1;
    static final int T2_MITIGATION = 2;
    static final int T3_IDENTITY   = 3;
    static final int T4_POLICY     = 4;
    static final int T5_FORWARDING = 5;

    // metadata masks por rol (mismos valores que M1)
    private static final long META_ALUMNO    = 0x02L;
    private static final long META_DOCENTE   = 0x03L;
    private static final long META_ADMIN_RED = 0x05L;
    private static final long META_CUARENTENA = 0x09L;
    private static final long META_MASK      = 0xFFL;

    // subredes por rol (del plan de direccionamiento)
    private static final IpPrefix SUBNET_ALUMNO    = IpPrefix.valueOf("10.20.0.0/16");
    private static final IpPrefix SUBNET_DOCENTE   = IpPrefix.valueOf("10.30.0.0/16");
    private static final IpPrefix SUBNET_ADMIN_RED = IpPrefix.valueOf("10.50.0.0/16");
    private static final IpPrefix SUBNET_INTRANET  = IpPrefix.valueOf("10.0.0.0/8");

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    private ApplicationId appId;
    private DeviceListener deviceListener;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.pucp.tel354.g5.pipeline");

        // instalar pipeline en todos los switches ya conectados
        for (Device device : deviceService.getAvailableDevices(Device.Type.SWITCH)) {
            initPipeline(device.id());
        }

        // escuchar nuevos switches que se conecten
        deviceListener = new InternalDeviceListener();
        deviceService.addListener(deviceListener);

        log.info("M2PipelineManager activo - pipeline T0-T5 instalado");
    }

    @Deactivate
    protected void deactivate() {
        deviceService.removeListener(deviceListener);
        flowRuleService.removeFlowRulesById(appId);
        log.info("M2PipelineManager detenido");
    }

    // inicializa el pipeline completo en un switch
    private void initPipeline(DeviceId deviceId) {
        log.info("Instalando pipeline en {}", deviceId);
        installT0Rules(deviceId);
        installT1Rules(deviceId);
        // T2 empieza vacio, M4 instala reglas dinamicamente
        // T3 empieza vacio, M1 instala reglas al autenticar
        installT4DefaultRules(deviceId);
        installT5Rules(deviceId);
    }

    // T0: reglas de arranque - Zero Trust desde el primer paquete
    private void installT0Rules(DeviceId deviceId) {
        // EAPOL -> Packet-In (prioridad maxima)
        installFlow(deviceId, T0_INGRESS,
                DefaultTrafficSelector.builder().matchEthType((short) 0x888E).build(),
                DefaultTrafficTreatment.builder().punt().build(),
                65535, 0, 0);

        // ARP -> Packet-In (para que ONOS aprenda topologia)
        installFlow(deviceId, T0_INGRESS,
                DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP).build(),
                DefaultTrafficTreatment.builder().punt().build(),
                1000, 0, 0);

        // DHCP (UDP dst 67) -> Packet-In
        installFlow(deviceId, T0_INGRESS,
                DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .matchIPProtocol(IPv4.PROTOCOL_UDP)
                        .matchUdpDst(TpPort.tpPort(67))
                        .build(),
                DefaultTrafficTreatment.builder().punt().build(),
                1000, 0, 0);

        // default drop (prioridad 0 - tabla vacia = drop en OpenFlow)
        installFlow(deviceId, T0_INGRESS,
                DefaultTrafficSelector.builder().build(),
                DefaultTrafficTreatment.builder().drop().build(),
                0, 0, 0);

        // transicion al resto del pipeline para trafico autenticado
        installFlow(deviceId, T0_INGRESS,
                DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_IPV4).build(),
                DefaultTrafficTreatment.builder().transition(T1_ANTISPOOFING).build(),
                500, 0, 0);
    }

    // T1: anti-spoofing basico - en produccion consultar tabla DHCP snooping
    private void installT1Rules(DeviceId deviceId) {
        // trafico valido pasa a T2
        // TODO: agregar validacion MAC+IP+puerto contra binding DHCP
        installFlow(deviceId, T1_ANTISPOOFING,
                DefaultTrafficSelector.builder().build(),
                DefaultTrafficTreatment.builder().transition(T2_MITIGATION).build(),
                100, 0, 0);
    }

    // T4: reglas por rol - se instalan al activar el pipeline
    private void installT4DefaultRules(DeviceId deviceId) {
        // Alumno (metadata=0x02): accede a su subred y a internet, NO a otras subredes
        installRoleRules(deviceId, META_ALUMNO,
                new IpPrefix[]{ SUBNET_ALUMNO },         // permitido
                new IpPrefix[]{ SUBNET_INTRANET });      // bloqueado si no es su subred

        // Docente (metadata=0x03): accede a toda la intranet
        installRoleRules(deviceId, META_DOCENTE,
                new IpPrefix[]{ SUBNET_INTRANET },
                new IpPrefix[]{});

        // Admin-Red (metadata=0x05): acceso total
        installRoleRules(deviceId, META_ADMIN_RED,
                new IpPrefix[]{ SUBNET_INTRANET },
                new IpPrefix[]{});

        // Cuarentena (metadata=0x09): drop todo
        installFlow(deviceId, T4_POLICY,
                DefaultTrafficSelector.builder()
                        .matchMetadata(META_CUARENTENA)
                        .build(),
                DefaultTrafficTreatment.builder().drop().build(),
                19999, 0, 0);

        log.debug("Reglas T4 instaladas en {}", deviceId);
    }

    private void installRoleRules(DeviceId deviceId, long metadata,
                                   IpPrefix[] allowed, IpPrefix[] blocked) {
        // reglas de bloqueo primero (mayor prioridad)
        for (IpPrefix subnet : blocked) {
            installFlow(deviceId, T4_POLICY,
                    DefaultTrafficSelector.builder()
                            .matchMetadata(metadata)
                            .matchIPDst(subnet)
                            .build(),
                    DefaultTrafficTreatment.builder().drop().build(),
                    19999, 0, 0);
        }

        // reglas de permiso hacia subredes propias
        for (IpPrefix subnet : allowed) {
            installFlow(deviceId, T4_POLICY,
                    DefaultTrafficSelector.builder()
                            .matchMetadata(metadata)
                            .matchIPDst(subnet)
                            .build(),
                    DefaultTrafficTreatment.builder().transition(T5_FORWARDING).build(),
                    20000, 0, 0);
        }

        // trafico hacia internet (0.0.0.0/0) -> gateway
        installFlow(deviceId, T4_POLICY,
                DefaultTrafficSelector.builder()
                        .matchMetadata(metadata)
                        .build(),
                DefaultTrafficTreatment.builder().transition(T5_FORWARDING).build(),
                18000, 0, 0);
    }

    // T5: reenvio basico por MAC aprendida
    private void installT5Rules(DeviceId deviceId) {
        // por ahora flood - en produccion ONOS aprende puertos por MAC
        installFlow(deviceId, T5_FORWARDING,
                DefaultTrafficSelector.builder().build(),
                DefaultTrafficTreatment.builder().flood().build(),
                100, 0, 0);
    }

    private void installFlow(DeviceId deviceId, int tableId,
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
                .makePermanent()
                .build();
        flowRuleService.applyFlowRules(rule);
    }

    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            if (event.type() == DeviceEvent.Type.DEVICE_ADDED ||
                event.type() == DeviceEvent.Type.DEVICE_AVAILABILITY_CHANGED) {
                DeviceId id = event.subject().id();
                if (deviceService.isAvailable(id)) {
                    log.info("Nuevo switch conectado: {}, inicializando pipeline", id);
                    initPipeline(id);
                }
            }
        }
    }
}
