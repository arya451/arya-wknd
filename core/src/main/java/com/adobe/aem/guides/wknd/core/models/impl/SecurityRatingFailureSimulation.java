/*
 *  Copyright 2019 Adobe Systems Incorporated
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.adobe.aem.guides.wknd.core.models.impl;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.models.annotations.Model;

/**
 * SIMULATION ONLY - Remove after testing.
 * This class intentionally introduces a Security Rating vulnerability (hardcoded password)
 * so that Cloud Manager code quality fails. Used to simulate pipeline failure scenario.
 * See: https://experienceleague.adobe.com/en/docs/experience-manager-cloud-manager/content/using/code-quality-testing#code-quality-testing-step
 * Security Rating &lt; B (blocker = E) causes pipeline failure.
 */
@Model(adaptables = SlingHttpServletRequest.class)
public class SecurityRatingFailureSimulation {

    // Intentionally hardcoded password - triggers SonarQube rule squid:S2068 (blocker vulnerability).
    // This will set Security Rating to E and fail the Cloud Manager code quality gate.
    private static final String API_PASSWORD = "mysecretpassword123";

    public String getApiPassword() {
        return API_PASSWORD;
    }
}
