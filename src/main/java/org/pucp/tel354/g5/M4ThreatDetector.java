package org.pucp.tel354.g5;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.*;
import org.onosproject.net.statistic.FlowStatisticService;
import org.onosproject.net.statistic.PortStatisticsService;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * M4 - ThreatDetector
 * Detecta y mitiga dos tipos de amenazas:
 *
 *   R3 - Ataques encubiertos: Suricata detecta via IDS -> alerta REST -> Flow-Mod en T2
 *   R4 - DDoS brute-force  : estadisticas OpenFlow (PortStatistics/FlowStatistics)
 *                            umbral > 10,000 pkt/s durante >= 5s -> bloqueo gradual en T2
 *
 * Las reglas de mitigacion van siempre en T2 con hard_timeout para auto-expirar.
 */
@Component(immediate = true)
public class M4ThreatDetector {

    private final Logger log = LoggerFactory.getLogger(getClass());

    // tabla de mitigacion
    private static final int T2_MITIGATION   = 2;
    private static final int PRIORITY_BLOCK  = 55000; // mayor que reglas normales
    private static final int PRIORITY_COVERT = 50000;

    // umbral DDoS: 10,000 pkt/s sostenido 5 segundos
    private static final long DDOS_THRESHOLD_PKTS = 10_000L;
    private static final int  DDOS_WINDOW_SECS    = 5;

    // puerto donde escucha el servidor REST de alertas de Suricata
    private static final int ALERT_LISTEN_PORT = 9200;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PortStatisticsService portStatisticsService;

    private ApplicationId appId;
    private ScheduledExecutorService scheduler;
    private ServerSocket alertSocket;

    // contadores para ventana DDoS: deviceId+port -> lista de muestras
    private final Map<String, Deque<Long>> ddosSamples = new ConcurrentHashMap<>();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.pucp.tel354.g5.threat");

        scheduler = Executors.newScheduledThreadPool(2);

        // polling de estadisticas OpenFlow cada 1 segundo (R4)
        scheduler.scheduleAtFixedRate(this::checkDdosStats, 1, 1, TimeUnit.SECONDS);

        // servidor REST para alertas de Suricata (R3)
        scheduler.submit(this::startAlertListener);

        log.info("M4ThreatDetector activo - umbral DDoS: {} pkt/s, ventana: {}s",
                DDOS_THRESHOLD_PKTS, DDOS_WINDOW_SECS);
    }

    @Deactivate
    protected void deactivate() {
        scheduler.shutdownNow();
        try {
            if (alertSocket != null) alertSocket.close();
        } catch (IOException ignored) {}
        flowRuleService.removeFlowRulesById(appId);
        log.info("M4ThreatDetector detenido");
    }

    // ---- R3: Ataques encubiertos via Suricata IDS ----

    private void startAlertListener() {
        try {
            alertSocket = new ServerSocket(ALERT_LISTEN_PORT);
            log.info("Escuchando alertas Suricata en puerto {}", ALERT_LISTEN_PORT);

            while (!Thread.currentThread().isInterrupted()) {
                try (Socket client = alertSocket.accept();
                     BufferedReader reader = new BufferedReader(
                             new InputStreamReader(client.getInputStream()))) {

                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }
                    processAlert(sb.toString());

                } catch (SocketException e) {
                    if (!alertSocket.isClosed()) {
                        log.error("Error en socket de alertas: {}", e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            log.error("No se pudo iniciar el listener de alertas: {}", e.getMessage());
        }
    }

    // alerta JSON de Suricata con campos: src_ip, src_mac, in_port, device_id, severity
    private void processAlert(String json) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode alert = mapper.readTree(json);

            String srcMac   = alert.get("src_mac").asText();
            String inPort   = alert.get("in_port").asText();
            String deviceId = alert.get("device_id").asText();
            String severity = alert.get("severity").asText("moderate");
            String attackType = alert.get("alert_type").asText("unknown");

            log.warn("Alerta R3 recibida: tipo={} src={} severidad={} switch={}",
                    attackType, srcMac, severity, deviceId);

            mitigateCovert(DeviceId.deviceId(deviceId),
                    MacAddress.valueOf(srcMac),
                    PortNumber.portNumber(inPort),
                    severity);

        } catch (Exception e) {
            log.error("Error procesando alerta Suricata: {}", e.getMessage());
        }
    }

    private void mitigateCovert(DeviceId deviceId, MacAddress srcMac,
                                  PortNumber inPort, String severity) {
        // regla exacta como en el HLD:
        // match(in_port=X, eth_src=MAC), priority=50000, action=drop,
        // idle_timeout=300, hard_timeout=3600
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(inPort)
                .matchEthSrc(srcMac)
                .build();

        TrafficTreatment treatment;
        int hardTimeout;

        switch (severity.toLowerCase()) {
            case "low":
                // rate-limit via meter (leve)
                treatment = DefaultTrafficTreatment.builder()
                        .setQueue(1) // queue de baja prioridad como rate-limit
                        .build();
                hardTimeout = 300;
                break;
            case "high":
                // bloqueo + mover a cuarentena
                treatment = DefaultTrafficTreatment.builder()
                        .drop()
                        .build();
                hardTimeout = 3600;
                // TODO: notificar a M1 para reasignar a VLAN 900
                break;
            default: // moderate
                treatment = DefaultTrafficTreatment.builder()
                        .drop()
                        .build();
                hardTimeout = 3600;
                break;
        }

        FlowRule blockRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(T2_MITIGATION)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(PRIORITY_COVERT)
                .withIdleTimeout(300)
                .withHardTimeout(hardTimeout)
                .fromApp(appId)
                .build();

        flowRuleService.applyFlowRules(blockRule);
        log.info("Mitigacion R3 aplicada: MAC={} switch={} timeout={}s",
                srcMac, deviceId, hardTimeout);
    }

    // ---- R4: DDoS brute-force via estadisticas OpenFlow ----

    private void checkDdosStats() {
        // TODO: iterar sobre deviceService para obtener todos los switches
        // por ahora el detector se activa cuando otra parte llama checkPort()
    }

    // llamado externamente o por scheduler con dispositivos reales
    public void checkPort(DeviceId deviceId, PortNumber port, long currentPkts) {
        String key = deviceId + ":" + port;
        Deque<Long> samples = ddosSamples.computeIfAbsent(key,
                k -> new ArrayDeque<>());

        samples.addLast(currentPkts);
        if (samples.size() > DDOS_WINDOW_SECS) {
            samples.removeFirst();
        }

        if (samples.size() < DDOS_WINDOW_SECS) return; // ventana incompleta

        // promedio de la ventana
        long avg = samples.stream().mapToLong(Long::longValue).sum() / samples.size();

        if (avg > DDOS_THRESHOLD_PKTS) {
            log.warn("DDoS detectado en {}:{} - {} pkt/s promedio (umbral: {})",
                    deviceId, port, avg, DDOS_THRESHOLD_PKTS);
            mitigateDdos(deviceId, port, avg);
            samples.clear(); // resetear ventana post-mitigacion
        }
    }

    private void mitigateDdos(DeviceId deviceId, PortNumber inPort, long pktRate) {
        // accion gradual segun intensidad
        if (pktRate < 1_000_000L) {
            // leve: rate-limit en T2
            applyDdosRule(deviceId, inPort, false, 300);
            log.info("DDoS leve - rate-limit aplicado en {}:{}", deviceId, inPort);

        } else if (pktRate < 5_000_000L) {
            // moderado: drop + alerta
            applyDdosRule(deviceId, inPort, true, 3600);
            log.warn("DDoS moderado - drop aplicado en {}:{}", deviceId, inPort);
            // TODO: enviar notificacion a M6 AdminConsole

        } else {
            // grave: drop + blackhole
            applyDdosRule(deviceId, inPort, true, 3600);
            // TODO: instalar blackhole route y mover a VLAN 900
            log.error("DDoS grave (>5Gbps) en {}:{} - activando blackhole", deviceId, inPort);
        }
    }

    private void applyDdosRule(DeviceId deviceId, PortNumber inPort,
                                boolean drop, int hardTimeout) {
        // match(in_port=X), priority=55000, action=drop, hard_timeout=3600
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(inPort)
                .build();

        TrafficTreatment treatment = drop
                ? DefaultTrafficTreatment.builder().drop().build()
                : DefaultTrafficTreatment.builder().setQueue(0).build();

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(T2_MITIGATION)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(PRIORITY_BLOCK)
                .withIdleTimeout(0)
                .withHardTimeout(hardTimeout)
                .fromApp(appId)
                .build();

        flowRuleService.applyFlowRules(rule);
    }
}
