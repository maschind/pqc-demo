package com.example.pqcdemo.controller;

import com.example.pqcdemo.model.CryptoCapabilitiesResponse;
import com.example.pqcdemo.service.CryptoCapabilitiesService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/crypto")
public class CryptoCapabilitiesController {

    private static final Logger logger = LoggerFactory.getLogger(CryptoCapabilitiesController.class);

    @Autowired
    private CryptoCapabilitiesService cryptoCapabilitiesService;

    @GetMapping(value = "/capabilities", produces = MediaType.APPLICATION_JSON_VALUE)
    public CryptoCapabilitiesResponse getCapabilities() {
        logger.info("GET /crypto/capabilities called");
        CryptoCapabilitiesResponse response = cryptoCapabilitiesService.getCapabilities();
        return response;
    }
}
