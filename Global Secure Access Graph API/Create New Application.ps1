# Prepare body for API access token retrieval
$clientID = ""
$ClientSecret = ""
$body = @{
    client_id = $clientID
    client_secret = $ClientSecret
    scope = "https://graph.microsoft.com/.default"
    grant_type = "client_credentials"
}

# Get API access token
$tenantID = ""
$TokenEndpoint = "https://login.microsoft.com/$tenantId/oauth2/v2.0/token"
$tokenResponse = Invoke-RestMethod -Uri $TokenEndpoint -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
$AccessToken = $tokenResponse.access_token
$Headers = @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

# Prepare the request body for instantiating the Private Access app
$ApplicationName = "New File Server"
$Body = @{
    displayName = $ApplicationName
} | ConvertTo-Json -Depth 99 -Compress

$params = @{
    Method  = 'POST'
    Uri = 'https://graph.microsoft.com/beta/applicationTemplates/8adf8e6e-67b2-4cf2-a259-e3dc5476c621/instantiate'
    Headers = $Headers
    Body = $Body
}
$newApp = Invoke-RestMethod @params

# Set the Private Access app to be accessible via the ZTNA client
$newAppId = $newApp.application.objectId
$body = @{
    onPremisesPublishing = @{
        applicationType = "nonwebapp"
        isAccessibleViaZTNAClient = "true"
    }
} | ConvertTo-Json -Depth 99 -Compress

$params = @{
    Method = 'PATCH'
    Uri = "https://graph.microsoft.com/beta/applications/$newAppId"
    Headers = $Headers
    Body = $body
}
Invoke-RestMethod @params

# Configure application segment
$body = @{
        destinationHost = "srvfile.domain.com"
        protocol = "tcp"
        ports = @('445-445')
        destinationType = "fqdn"
} | ConvertTo-Json -Depth 99 -Compress

$params = @{
        Method = 'POST'
        Uri = "https://graph.microsoft.com/beta/applications/$newAppId/onPremisesPublishing/segmentsConfiguration/microsoft.graph.ipSegmentConfiguration/applicationSegments"
        Headers = $Headers
        Body = $body
}
Invoke-RestMethod @params

# Assign the connector group to the app
$ConnectorGroupName = "Default"
$ConnectorGroupId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationproxy/connectorGroups?`$Filter=name eq '$ConnectorGroupName'" -Headers $Headers).Value.Id

$Body = @{
    "@odata.id" = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationproxy/connectorGroups/$ConnectorGroupId"    
} | ConvertTo-Json -Depth 99 -Compress

$params = @{
        Method  = 'PUT'
        Uri     = "https://graph.microsoft.com/beta/applications/$newAppId/connectorGroup/`$ref"
        Headers = $Headers
        Body    = $Body
}
Invoke-RestMethod @params