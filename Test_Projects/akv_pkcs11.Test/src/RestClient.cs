/*******************************************************************************
 *
 *                                   GRADIANT
 *
 *     Galician Research And Development center In AdvaNced Telecommunication
 *
 *
 * Copyright (c) 2019 by Gradiant. All rights reserved.
 * Licensed under the Mozilla Public License v2.0 (the "LICENSE").
 * https://github.com/Gradiant/BlackICE_Connect/LICENSE
 *******************************************************************************/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading;

public enum HttpVerb
{
    GET,
    POST,
    PUT,
    DELETE
}
namespace akv_pkcs11.Test
{
    public class ConfVariables
    {
        public string Host { get; set; }
        public string ApiVersion { get; set; }
        public string TenantID { get; set; }
        public string ClientID { get; set; }
        public string Password { get; set; }
        public string Resource { get; set; }
        public string Auth_ApiVersion { get; set; }
        public string Auth_Url { get; set; }
    }
    public class ListCert
    {
        public Certificates[] Value { get; set; }
        public string NextLink { get; set; }
    }
    public class Certificates
    {
        public string Id { get; set; }
        public string X5t { get; set; }
        public Attributes Attributes { get; set; }
    }
    public class Attributes
    {
        public bool Enabled { get; set; }
        public long Nbf { get; set; }
        public long Exp { get; set; }
        public long Created { get; set; }
        public long Updated { get; set; }
    }
    public class Token
    {
        public string Token_type { get; set; }
        public string Expires_in { get; set; }
        public string Ext_expires_in { get; set; }
        public string Expires_on { get; set; }
        public string Not_before { get; set; }
        public string Resource { get; set; }
        public string Access_token { get; set; }
    }
    public class CertificateOperation
    {
        public bool Cancellation_requested { get; set; }
        public string Csr { get; set; }
        public Error Error { get; set; }
        public string Id { get; set; }
        public IssuerParameters Issuer { get; set; }
        public string Request_id { get; set; }
        public string Status { get; set; }
        public string Status_details { get; set; }
        public string Target { get; set; }

    };
    public class Error
    {
        public string Code { get; set; }
        public Error Innererror { get; set; }
        public string Message { get; set; }
    }
    public class CreateCertificateBody
    {
        public CertificateAttributes Attributes { get; set; }
        public CertificatePolicy Policy { get; set; }
        public List<Tuple<string, string>> Tags { get; set; }
    }
    public class CertificateAttributes : Attributes
    {
        public string RecoveryLevel { get; set; }
    }
    public class CertificatePolicy
    {
        public CertificateAttributes CertificateAttributes { get; set; }
        public string Id { get; set; }
        public IssuerParameters Issuer { get; set; }
        public KeyProperties Key_props { get; set; }
        public LifetimeAction[] Lifetime_actions { get; set; }
        public SecretProperties Secret_props { get; set; }
        public X509CertificateProperties X509_props { get; set; }
    }
    public class IssuerParameters
    {
        public string Cty { get; set; }
        public string Name { get; set; }
    }
    public class KeyProperties
    {
        public bool Exportable { get; set; }
        public int Key_size { get; set; }
        public string Kty { get; set; }
        public bool Reuse_key { get; set; }
    }
    public class LifetimeAction
    {
        public string Action { get; set; }
        public Trigger Trigger { get; set; }
    }
    public class Trigger
    {
        public int Days_before_expiry { get; set; }
        public int Lifetime_percentage { get; set; }
    }
    public class SubjectAlternativeNames
    {
        public string[] Dns_names { get; set; }
        public string[] Emails { get; set; }
        public string[] Upns { get; set; }
    }
    public class SecretProperties
    {
        public string contentType { get; set; }
    }
    public class X509CertificateProperties
    {
        public string[] Ekus { get; set; }
        public string[] Key_usage { get; set; }
        public SubjectAlternativeNames Sans { get; set; }
        public string Subject { get; set; }
        public int Validity_months { get; set; }
    }
    class RestClient
    {
        public string EndPoint { get; set; }
        public HttpVerb Method { get; set; }
        public string ContentType { get; set; }
        public string PostData { get; set; }
        public string Accept { get; set; }
        public string Authorization { get; set; }

        public RestClient()
        {
            EndPoint = "";
            Method = HttpVerb.GET;
            ContentType = "application/x-www-form-urlencoded";
            PostData = "";
            Accept = "application/json";
            Authorization = "";
        }
        public RestClient(string endpoint)
        {
            EndPoint = endpoint;
            Method = HttpVerb.GET;
            ContentType = "application/x-www-form-urlencoded";
            PostData = "";
            Accept = "application/json";
            Authorization = "";
        }
        public RestClient(string endpoint, HttpVerb method)
        {
            EndPoint = endpoint;
            Method = method;
            ContentType = "application/x-www-form-urlencoded";
            PostData = "";
            Accept = "application/json";
            Authorization = "";
        }

        public RestClient(string endpoint, HttpVerb method, string postData)
        {
            EndPoint = endpoint;
            Method = method;
            ContentType = "application/x-www-form-urlencoded";
            PostData = postData;
            Accept = "application/json";
            Authorization = "";
        }

        public RestClient(string endpoint, HttpVerb method, string postData, string contentType)
        {
            EndPoint = endpoint;
            Method = method;
            ContentType = contentType;
            PostData = postData;
            Accept = "application/json";
            Authorization = "";
        }
        public RestClient(string endpoint, HttpVerb method, string postData, string contentType, string authorization)
        {
            EndPoint = endpoint;
            Method = method;
            ContentType = contentType;
            PostData = postData;
            Accept = "application/json";
            Authorization = authorization;
        }
        public RestClient(string endpoint, HttpVerb method, string postData, string contentType, string authorization, string accept)
        {
            EndPoint = endpoint;
            Method = method;
            ContentType = contentType;
            PostData = postData;
            Accept = accept;
            Authorization = authorization;
        }

        public string MakeRequest()
        {
            return MakeRequest("");
        }

        public string MakeRequest(string parameters)
        {
            var request = (HttpWebRequest)WebRequest.Create(EndPoint + parameters);
            request.Method = Method.ToString();
            request.ContentLength = 0;
            request.ContentType = ContentType;
            if (Authorization != "")
            {
                request.PreAuthenticate = true;
                request.Headers.Add("Authorization", "Bearer " + Authorization);

            }
            request.Accept = Accept;
            if (!string.IsNullOrEmpty(PostData) && Method == HttpVerb.POST)
            {
                var bytes = Encoding.GetEncoding("iso-8859-1").GetBytes(PostData);
                request.ContentLength = bytes.Length;

                using (var writeStream = request.GetRequestStream())
                {
                    writeStream.Write(bytes, 0, bytes.Length);
                }
            }

            using (var response = (HttpWebResponse)request.GetResponse())
            {
                var responseValue = string.Empty;

                if (response.StatusCode != HttpStatusCode.OK && response.StatusCode != HttpStatusCode.Accepted)
                {
                    var message = String.Format("Request failed. Received HTTP {0}", response.StatusCode);
                    throw new ApplicationException(message);
                }

                // grab the response
                using (var responseStream = response.GetResponseStream())
                {
                    if (responseStream != null)
                        using (var reader = new StreamReader(responseStream))
                        {
                            responseValue = reader.ReadToEnd();
                        }
                }
                return responseValue;
            }
        }
        public static string GetToken()
        {
            Token token;
            ConfVariables confVariables = GetConfigurationVariables();
            if (confVariables == null) return "";
            if ((confVariables.TenantID == "") || (confVariables.ClientID == "") || (confVariables.Password == ""))
                return "";
            string getTokenString = "/oauth2/token?api-version=";
            string endPoint = confVariables.Auth_Url + "/" + confVariables.TenantID + getTokenString + confVariables.ApiVersion;
            var client = new RestClient(endPoint)
            {
                Method = HttpVerb.POST,
                PostData = "grant_type=client_credentials&resource=" + confVariables.Resource + "&client_id=" + confVariables.ClientID + "&client_secret=" + confVariables.Password
            };
            var json = client.MakeRequest();
            token = JsonConvert.DeserializeObject<Token>(json);
            return token.Access_token;
        }

        public static string[] NonExistingCertificates(string[] certificates)
        {
            if (certificates == null)
            {
                throw new ArgumentNullException(nameof(certificates));
            }
            string token = GetToken();
            Assert.AreNotEqual("", token);
            ConfVariables confVariables = GetConfigurationVariables();
            Assert.AreNotEqual(null, confVariables);
            string listCert = "certificates?api-version=";
            string endPoint = confVariables.Host + listCert + confVariables.ApiVersion;
            var client = new RestClient(endPoint)
            {
                Method = HttpVerb.GET,
                Authorization = token,
                ContentType = "application/json"
            };
            var json = client.MakeRequest();
            ListCert listCertificate = JsonConvert.DeserializeObject<ListCert>(json);
            foreach (Certificates cert in listCertificate.Value)
            {
                for (int i = 0; i < certificates.Length; i++)
                {
                    if (cert.Id.Contains(certificates[i]))
                    {
                        certificates = certificates.Where(w => w != certificates[i]).ToArray();
                    }
                }
            }
            while (listCertificate.NextLink != null)
            {
                var newClient = new RestClient(listCertificate.NextLink)
                {
                    Method = HttpVerb.GET,
                    Authorization = token,
                    ContentType = "application/json"
                };
                json = newClient.MakeRequest();
                listCertificate = JsonConvert.DeserializeObject<ListCert>(json);
                foreach (Certificates cert in listCertificate.Value)
                {
                    for (int i = 0; i < certificates.Length; i++)
                    {
                        if (cert.Id.Contains(certificates[i]))
                        {
                            certificates = certificates.Where(w => w != certificates[i]).ToArray();
                        }
                    }
                }
            }
            return certificates;
        }

        public static void CreateCertificates(string[] certificates)
        {
            if (certificates == null)
            {
                throw new ArgumentNullException(nameof(certificates));
            }
            string token = GetToken();
            Assert.AreNotEqual("", token);
            ConfVariables confVariables = GetConfigurationVariables();
            Assert.AreNotEqual(null, confVariables);
            foreach (string cert in certificates)
            {
                CreateCertificateBody createCert = new CreateCertificateBody()
                {
                    Policy = new CertificatePolicy
                    {
                        Key_props = new KeyProperties
                        {
                            Exportable = true,
                            Kty = "RSA",
                            Key_size = 2048,
                            Reuse_key = true
                        },
                        Secret_props = new SecretProperties
                        {
                            contentType = "application/x-pkcs12"
                        },
                        X509_props = new X509CertificateProperties
                        {
                            Subject = "CN=" + cert + ".com",
                            Key_usage = new string[] { "DataEncipherment", "DigitalSignature", "KeyEncipherment" },
                            Validity_months = 12,
                        },
                        Issuer = new IssuerParameters
                        {
                            Name = "Self"
                        }
                    }
                };
                string listCert = "certificates/" + cert + "/create?api-version=";
                string endPoint = confVariables.Host + listCert + confVariables.ApiVersion;
                var client = new RestClient(endPoint)
                {
                    Method = HttpVerb.POST,
                    Authorization = token,
                    ContentType = "application/json",
                    PostData = JsonConvert.SerializeObject(createCert).ToString()
                };
                var json = client.MakeRequest();
            }
            foreach (string cert in certificates)
            {
                CertificateOperation CertificateCreation;
                int count = 0;
                string listCert = "certificates/" + cert + "/pending?api-version=";
                string endPoint = confVariables.Host + listCert + confVariables.ApiVersion;
                var client = new RestClient(endPoint)
                {
                    Method = HttpVerb.GET,
                    Authorization = token,
                    ContentType = "application/json"
                };
                do
                {
                    var json = client.MakeRequest();
                    CertificateCreation = JsonConvert.DeserializeObject<CertificateOperation>(json);
                    if ((CertificateCreation.Status.Contains("completed")) || count > 10)
                    {
                        break;
                    }
                    count++;
                    Thread.Sleep(2000);
                } while (1 == 1);
            }
        }
        public static ConfVariables GetConfigurationVariables()
        {
            try
            {
                ConfVariables confVariables = new ConfVariables();
                string[] bufferedFile = File.ReadAllLines("BlackICEconnect.cnf");
                foreach (string line in bufferedFile)
                {
                    var result = from Match match in Regex.Matches(line, "\"([^\"]*)\"") select match.ToString();
                    if ((line.Contains("AUTH_URL")) && !line.Contains("#"))
                    {
                        confVariables.Auth_Url = result.First().ToString().Substring(1, result.First().ToString().Length - 2);
                    }
                    if ((line.Contains("HOST")) && !line.Contains("#"))
                    {
                        confVariables.Host = result.First().ToString().Substring(1, result.First().ToString().Length - 2);
                    }
                    if ((line.Contains("AUTH_APIVERSION")) && !line.Contains("#"))
                    {
                        confVariables.Auth_ApiVersion = result.First().ToString().Substring(1, result.First().ToString().Length - 2);
                    }
                    if ((line.Contains("TENANTID")) && !line.Contains("#"))
                    {
                        confVariables.TenantID = result.First().ToString().Substring(1, result.First().ToString().Length - 2);
                    }
                    if ((line.Contains("CLIENTID")) && !line.Contains("#"))
                    {
                        confVariables.ClientID = result.First().ToString().Substring(1, result.First().ToString().Length - 2);
                    }
                    if ((line.Contains("PASSWORD")) && !line.Contains("#"))
                    {
                        confVariables.Password = result.First().ToString().Substring(1, result.First().ToString().Length - 2);
                    }
                    if ((line.Contains("RESOURCE")) && !line.Contains("#"))
                    {
                        confVariables.Resource = result.First().ToString().Substring(1, result.First().ToString().Length - 2);
                    }
                }
                if (confVariables.Auth_Url == null)
                {
                    confVariables.Auth_Url = "https://login.windows.net";
                }
                if (confVariables.Auth_ApiVersion == null)
                {
                    confVariables.Auth_ApiVersion = "1.0";
                }
                if (confVariables.ApiVersion == null)
                {
                    confVariables.ApiVersion = "2016-10-01";
                }
                if (confVariables.Resource == null)
                {
                    confVariables.Resource = "https://vault.azure.net";
                }
                return confVariables;
            }
            catch { return null; }
        }
    }
}
