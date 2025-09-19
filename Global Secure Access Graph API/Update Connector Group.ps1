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

# Current and new connector group name
$ConnectorGroupName = ""
$NewConnectorGroupName = ""

$params = @{
    Method = 'Get'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/?`$Filter=name eq '$ConnectorGroupName'"
    Headers = $Headers
}
$ConnectorGroup = Invoke-RestMethod @params
$ConnectorGroupId = $ConnectorGroup.value.id

$Body = @{
    name = $NewConnectorGroupName
} | ConvertTo-Json -Depth 99 -Compress

$params = @{
    Method = 'PATCH'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$ConnectorGroupId"
    Headers = $Headers
    Body = $body
}
Invoke-RestMethod @params

# Change connector group region location
$ConnectorGroupName = ""
$ConnectorGroupRegion = "" #nam = North America - eur =  Europe - aus = Australia - asia = Asia - ind = India

$params = @{
    Method = 'Get'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/?`$Filter=name eq '$ConnectorGroupName'"
    Headers = $Headers
}
$ConnectorGroup = Invoke-RestMethod @params
$ConnectorGroupId = $ConnectorGroup.value.id

$Body = @{
    region = $ConnectorGroupRegion
} | ConvertTo-Json -Depth 99 -Compress

$params = @{
    Method = 'PATCH'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$ConnectorGroupId"
    Headers = $Headers
    Body = $body
}
Invoke-RestMethod @params