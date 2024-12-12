<?php

class HetznerObjectStorage
{
    private $endpointUrl;
    private $accessKey;
    private $secretKey;
    private $region;

    public function __construct($endpointUrl, $accessKey, $secretKey, $region)
    {
        $this->endpointUrl = $endpointUrl;
        $this->accessKey = $accessKey;
        $this->secretKey = $secretKey;
        $this->region = $region;

        if (!filter_var("https://" . $this->endpointUrl, FILTER_VALIDATE_URL)) {  // Adding https:// before validation
            throw new InvalidArgumentException("Invalid endpoint URL provided.");
        }

        // Error handling for missing credentials moved to individual methods as needed
    }
    private function getSigningKey($datePrefix)
    {
        $dateKey = hash_hmac('sha256', $datePrefix, 'AWS4' . $this->secretKey, true);
        $regionKey = hash_hmac('sha256', $this->region, $dateKey, true);
        $serviceKey = hash_hmac('sha256', 's3', $regionKey, true);
        return hash_hmac('sha256', 'aws4_request', $serviceKey, true);
    }

    private function getAuthorizationHeader($method, $path, $headers = [], $body = '')
    { // Removed unused $expires parameter
        $date = gmdate('Ymd\THis\Z');
        $datePrefix = gmdate('Ymd');

          //Corrected Host Header
        $host = parse_url($this->endpointUrl, PHP_URL_HOST);
         if(empty($host)){
             $host = $this->endpointUrl; // Use as is if it's already a host/subdomain
         }

        $canonicalHeaders = [
            'host' => $host,  // Use the extracted or provided host
            'x-amz-content-sha256' => hash('sha256', $body), // Added content-sha256 header
            'x-amz-date' => $date,
        ];

        ksort($canonicalHeaders);

        foreach ($headers as $key => $value) {
            $canonicalHeaders[strtolower($key)] = trim($value);
        }


        $canonicalHeadersString = '';
        foreach ($canonicalHeaders as $key => $value) {
            $canonicalHeadersString .= $key . ':' . $value . "\n";
        }

        $signedHeaders = implode(';', array_keys($canonicalHeaders));


        $canonicalRequest = "{$method}\n{$path}\n\n{$canonicalHeadersString}\n{$signedHeaders}\n" . $canonicalHeaders['x-amz-content-sha256'];

        $scope = $datePrefix . '/' . $this->region . '/s3/aws4_request';

        $stringToSign = "AWS4-HMAC-SHA256\n{$date}\n{$scope}\n" . hash('sha256', $canonicalRequest);

        $signingKey = $this->getSigningKey($datePrefix);
        $signature = hash_hmac('sha256', $stringToSign, $signingKey);

      // Return the Authorization header as a single string always
        return "Authorization: AWS4-HMAC-SHA256 Credential={$this->accessKey}/{$scope}, SignedHeaders={$signedHeaders}, Signature={$signature}";
    }
    public function setCorsPolicy($bucketName, $corsPolicyXml)
    {
        // Validate inputs
        if (!is_string($bucketName) || empty($bucketName)) {
            throw new InvalidArgumentException("Bucket name must be a non-empty string.");
        }
        if (!is_string($corsPolicyXml) || empty($corsPolicyXml)) {
            throw new InvalidArgumentException("CORS policy XML must be a non-empty string.");
        }

        $url =  "https://" . $bucketName . "." . $this->region . "." . $this->endpointUrl . "/?cors"; //Corrected URL
        echo $url;
        $headers = [
            'Content-Type' => 'application/xml',
            'Content-Length' => strlen($corsPolicyXml),
              // Add other necessary headers here if required
        ];

        $authHeader = $this->getAuthorizationHeader('PUT', '/?cors', $headers, $corsPolicyXml);


        $combinedHeaders = $headers;  //Start with $headers, which is an array

      // Add the authorization header to the array
       $combinedHeaders['Authorization'] = $authHeader;



        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL,$url); // Corrected URL
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
        curl_setopt($ch, CURLOPT_HTTPHEADER, $combinedHeaders); // Use the combined headers array
        curl_setopt($ch, CURLOPT_POSTFIELDS, $corsPolicyXml);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true); // Include headers in the response
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Disable SSL verification if using a self-signed certificate
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // Disable SSL host verification if using a self-signed certificate

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($httpCode !== 200 && $httpCode !== 204) {
            // Print the response body for more info
            $responseError = curl_error($ch);
            echo "Error: HTTP Code: {$httpCode}, Response: {$response}, Error: {$responseError}";
        }

        curl_close($ch);
        return $response;
    }
    

}


?>
