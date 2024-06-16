package com.adls.metriccert;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class MetricSert {
    private final Map<Object, Object> sertGaugeMap = new HashMap<>();
    private Counter sertCounter;
    @Autowired
    private MeterRegistry meterRegistry;

    @PostConstruct
    public void init() throws Exception {
        sertCounter = meterRegistry.counter("certificates_counter");
        setMetrics();
    }

    private void setMetrics() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("/Users/admin/Library/Java/JavaVirtualMachines/openjdk-17.0.1/Contents/Home/lib/security/cacerts"), "changeit".toCharArray());
        var aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            var alias = aliases.nextElement();
            if (!keyStore.isCertificateEntry(alias)) continue;
            Date notBefore = ((java.security.cert.X509Certificate) keyStore.getCertificate(alias)).getNotBefore();
            Date notAfter = ((java.security.cert.X509Certificate) keyStore.getCertificate(alias)).getNotAfter();
            long daysToExpiration = (notAfter.getTime() - notBefore.getTime()) / (1000 * 60 * 60 * 24);

            sertCounter.increment();
            Gauge.builder(alias, sertGaugeMap, tag -> daysToExpiration).register(meterRegistry);

        }
    }
}
