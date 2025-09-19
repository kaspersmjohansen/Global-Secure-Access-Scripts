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

# Prepare the request body
$ConnectorGroupName = ""
$IsDefaultConnectorGroup = "" # 'true' or 'false' 
$ConnectorGroupRegion = "" # 'nam' = North America - 'eur' =  Europe - 'aus' = Australia - 'asia' = Asia - 'ind' = India
$Body = @{
    name = $ConnectorGroupName
    isDefault = $IsDefaultConnectorGroup
    region = $ConnectorGroupRegion
} | ConvertTo-Json -Depth 99 -Compress

# Create Connector Group
$params = @{
    Method  = 'POST'
    Uri = 'https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups'
    Headers = $Headers
    Body = $Body
}
Invoke-RestMethod @params