package org.pucp.tel354.g5;

import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.flow.*;
import org.onosproject.net.packet.*;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.*;
import java.util.*;

/**
 * M1 - AuthManager
 * Maneja autenticacion 802.1X en la red SDN del campus PUCP.
 * Flujo: Supplicant -> Switch (EAPOL) -> Packet-In -> ONOS -> RADIUS -> LDAP
 * Al recibir Access-Accept instala regla en T3 con metadata del rol.
 */
@Component(immediate = true)
public class M1AuthManager {

    private final Logger log = LoggerFactory.getLogger(getClass());

    // puertos RADIUS y tabla de identidad
    private static final int RADIUS_PORT = 1812;
    private static final int TABLE_T3_IDENTITY = 3;
    private static final int TABLE_T0_INGRESS  = 0;
    private static final int PRIORITY_EAPOL    = 65535;
    private static final int PRIORITY_ARP      = 1000;
    private static final int PRIORITY_DHCP     = 1000;

    // metadata por rol (igual que en el HLD)
    private static final long META_INVITADO     = 0x01L;
    private static final long META_ALUMNO       = 0x02L;
    private static final long META_DOCENTE      = 0x03L;
    private static final long META_ADMIN        = 0x04L;
    private static final long META_ADMIN_RED    = 0x05L;
    private static final long META_CUARENTENA   = 0x09L;

    // VLAN por rol
    private static final short VLAN_INVITADO    = 100;
    private static final short VLAN_ALUMNO      = 200;
    private static final short VLAN_DOCENTE     = 300;
    private static final short VLAN_ADMIN       = 400;
    private static final short VLAN_ADMIN_RED   = 500;
    private static final short VLAN_CUARENTENA  = 900;

    // IP del servidor RADIUS (FreeRADIUS)
    private static final String RADIUS_SERVER = "10.50.0.10";
    private static final String RADIUS_SECRET = "pucp_secret_2026"; // TODO: mover a config

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    private ApplicationId appId;
    private PacketProcessor processor;

    // mapa MAC -> estado de autenticacion en curso
    private final Map<MacAddress, AuthSession> sessions = new HashMap<>();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.pucp.tel354.g5.auth");
        processor = new EapolPacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(2));
        log.info("M1AuthManager iniciado - app: {}", appId);
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        flowRuleService.removeFlowRulesById(appId);
        log.info("M1AuthManager detenido");
    }

    // instala las reglas de arranque en T0 para todos los switches
    // esto lo llama M2PipelineManager al detectar un nuevo switch
    public void installStartupRules(DeviceId deviceId) {
        // EAPOL -> Packet-In (prioridad maxima, sin timeout)
        TrafficSelector eapol = DefaultTrafficSelector.builder()
                .matchEthType((short) 0x888E)
                .build();
        TrafficTreatment toController = DefaultTrafficTreatment.builder()
                .punt()
                .build();
        installRule(deviceId, TABLE_T0_INGRESS, eapol, toController, PRIORITY_EAPOL, 0, 0);

        // ARP -> Packet-In
        TrafficSelector arp = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP)
                .build();
        installRule(deviceId, TABLE_T0_INGRESS, arp, toController, PRIORITY_ARP, 0, 0);

        // DHCP (UDP dst 67) -> Packet-In
        TrafficSelector dhcp = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpDst(TpPort.tpPort(67))
                .build();
        installRule(deviceId, TABLE_T0_INGRESS, dhcp, toController, PRIORITY_DHCP, 0, 0);

        log.info("Reglas de arranque T0 instaladas en {}", deviceId);
    }

    private class EapolPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) return;

            InboundPacket pkt = context.inPacket();
            Ethernet eth = pkt.parsed();
            if (eth == null) return;

            // solo procesamos EAPOL
            if (eth.getEtherType() != (short) 0x888E) return;

            MacAddress srcMac = eth.getSourceMAC();
            ConnectPoint cp = pkt.receivedFrom();

            log.debug("EAPOL recibido desde {} en {}", srcMac, cp);

            // iniciamos o continuamos sesion de autenticacion
            AuthSession session = sessions.computeIfAbsent(srcMac,
                    mac -> new AuthSession(mac, cp));

            byte[] eapPayload = eth.getPayload().serialize();
            handleEap(session, eapPayload);
            context.block();
        }
    }

    private void handleEap(AuthSession session, byte[] eapData) {
        // empaquetamos en Access-Request RADIUS y enviamos a FreeRADIUS
        // en produccion esto usaria la app AAA de ONOS o un cliente RADIUS real
        try {
            RadiusClient radius = new RadiusClient(RADIUS_SERVER, RADIUS_PORT, RADIUS_SECRET);
            String role = radius.authenticate(session.mac.toString(), eapData);

            if (role != null) {
                onAuthSuccess(session, role);
            } else {
                onAuthFailure(session);
            }
        } catch (Exception e) {
            log.error("Error comunicando con RADIUS: {}", e.getMessage());
            onAuthFailure(session);
        }
    }

    private void onAuthSuccess(AuthSession session, String role) {
        long metadata = roleToMetadata(role);
        short vlan     = roleToVlan(role);

        log.info("Autenticacion exitosa: MAC={} rol={} meta=0x{} VLAN={}",
                session.mac, role, Long.toHexString(metadata), vlan);

        // instalar regla en T3: match(eth_src=MAC) -> set_metadata(rol), set_vlan, goto T4
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthSrc(session.mac)
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .writeMetadata(metadata, 0xFFL)
                .setVlanId(VlanId.vlanId(vlan))
                .transition(4) // goto T4
                .build();

        installRule(session.connectPoint.deviceId(), TABLE_T3_IDENTITY,
                selector, treatment, 20000, 0, 3600);

        sessions.remove(session.mac);
    }

    private void onAuthFailure(AuthSession session) {
        log.warn("Autenticacion fallida para MAC={}, asignando cuarentena", session.mac);

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthSrc(session.mac)
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .writeMetadata(META_CUARENTENA, 0xFFL)
                .setVlanId(VlanId.vlanId(VLAN_CUARENTENA))
                .transition(4)
                .build();

        installRule(session.connectPoint.deviceId(), TABLE_T3_IDENTITY,
                selector, treatment, 19000, 0, 300);

        sessions.remove(session.mac);
    }

    private long roleToMetadata(String role) {
        switch (role.toLowerCase()) {
            case "alumno":      return META_ALUMNO;
            case "docente":     return META_DOCENTE;
            case "admin":       return META_ADMIN;
            case "admin_red":   return META_ADMIN_RED;
            case "invitado":    return META_INVITADO;
            default:            return META_CUARENTENA;
        }
    }

    private short roleToVlan(String role) {
        switch (role.toLowerCase()) {
            case "alumno":      return VLAN_ALUMNO;
            case "docente":     return VLAN_DOCENTE;
            case "admin":       return VLAN_ADMIN;
            case "admin_red":   return VLAN_ADMIN_RED;
            case "invitado":    return VLAN_INVITADO;
            default:            return VLAN_CUARENTENA;
        }
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

    // clase interna para trackear estado de una sesion 802.1X en curso
    private static class AuthSession {
        MacAddress mac;
        ConnectPoint connectPoint;
        long startTime;

        AuthSession(MacAddress mac, ConnectPoint cp) {
            this.mac = mac;
            this.connectPoint = cp;
            this.startTime = System.currentTimeMillis();
        }
    }

    // stub del cliente RADIUS - en produccion reemplazar con libreria TinyRadius o ONOS AAA
    private static class RadiusClient {
        private final String server;
        private final int port;
        private final String secret;

        RadiusClient(String server, int port, String secret) {
            this.server = server;
            this.port = port;
            this.secret = secret;
        }

        // retorna el rol del usuario o null si falla autenticacion
        String authenticate(String identity, byte[] eapData) throws Exception {
            // TODO: implementar RADIUS Access-Request real con TinyRadius
            // por ahora simulamos la respuesta para pruebas en Mininet
            if (identity.startsWith("00:00:00")) return null; // MAC de prueba falla
            return "alumno"; // default para demo
        }
    }
}
