using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NativeOidcMockProvider
{
    // Expected requests in order:
    // 1. Refresh request for consumer with old-refresh token
    // 2. Revoke request for new-refresh token
    public class Program
    {
        private static int expectedRequestCount = 2;
        private static List<string> receivedRequests = new List<string>();

        public static async Task Main(string[] args)
        {
            Console.WriteLine("Mock OIDC provider starting...");

            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            // Output the port number on the first line for scripts to capture
            var localEndpoint = ((IPEndPoint)listener.LocalEndpoint).Address + ":" + listener.Port;
            Console.WriteLine(localEndpoint);

            var cancellationTokenSource = new CancellationTokenSource();
            var timer = new System.Timers.Timer(60000); // 60 second timeout
            timer.Elapsed += (s, e) => {
                Console.Error.WriteLine("Mock provider timeout: not all expected requests received");
                cancellationTokenSource.Cancel();
            };
            timer.AutoReset = false;
            timer.Start();

            try
            {
                while (expectedRequestCount > 0 && !cancellationTokenSource.IsCancellationRequested)
                {
                    var client = await listener.AcceptAsync();
                    using var reader = new StreamReader(client.GetNetworkStream());
                    var requestLine = await reader.ReadLineAsync();
                    if (requestLine == null) continue;

                    var parts = requestLine.Split(new[] { ' ' }, 2);
                    var method = parts[0];
                    var path = parts.Length > 1 ? parts[1].Split('?', 2)[0] : "/";

                    var requestBody = new StringBuilder();
                    var buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = await client.GetNetworkStream().ReadAsync(buffer, 0, buffer.Length)) > 0)
                    {
                        requestBody.Append(Encoding.ASCII.GetString(buffer, 0, bytesRead));
                    }

                    string requestInfo = $"[{DateTime.Now:HH:mm:ss.fff}] {method} {path}";
                    if (requestBody.Length > 0)
                    {
                        requestInfo += "\n" + requestBody.ToString();
                    }
                    Console.WriteLine(requestInfo);

                    receivedRequests.Add(requestInfo);

                    // Determine what response to send based on the path and body
                    string? responseHtml;
                    int exitCode;

                    if (path == "/token")
                    {
                        // Token endpoint - refresh request
                        var form = ParseFormData(requestBody.ToString());
                        
                        if (form.TryGetValue("grant_type", out var grantType) && 
                            grantType.ToString().Trim() == "refresh_token" &&
                            form.TryGetValue("refresh_token", out var refreshToken) &&
                            form.TryGetValue("client_id", out var clientId) &&
                            refreshToken.ToString().Trim() == "old-refresh" &&
                            clientId.ToString().Trim() == "consumer")
                        {
                            // Successful refresh response
                            responseHtml = @"{""access_token"":""new-access"",""token_type"":""Bearer"",""expires_in"":3600,""refresh_token"":""new-refresh""}";
                        }
                        else
                        {
                            // Wrong request - unexpected token type or parameters
                            Console.Error.WriteLine($"Unexpected token request: {requestInfo}");
                            exitCode = 2; // Unexpected request
                            break;
                        }
                    }
                    else if (path == "/revoke")
                    {
                        // Revoke endpoint
                        var form = ParseFormData(requestBody.ToString());
                        
                        if (form.TryGetValue("token", out var token) &&
                            form.TryGetValue("token_type_hint", out var tokenTypeHint) &&
                            form.TryGetValue("client_id", out var revokeClientId) &&
                            token.ToString().Trim() == "new-refresh" &&
                            tokenTypeHint.ToString().Trim() == "refresh_token" &&
                            revokeClientId.ToString().Trim() == "consumer")
                        {
                            // Successful revoke response (empty body, 200 OK)
                            responseHtml = string.Empty;
                        }
                        else
                        {
                            // Wrong request - unexpected token or parameters
                            Console.Error.WriteLine($"Unexpected revoke request: {requestInfo}");
                            exitCode = 2; // Unexpected request
                            break;
                        }
                    }
                    else if (path == "/health")
                    {
                        // Health check endpoint - doesn't count against expected requests
                        responseHtml = @"{""status"":""ok""}";
                        Console.WriteLine($"Health check: received {receivedRequests.Count} / {expectedRequestCount} requests");
                    }
                    else
                    {
                        // Unknown path
                        Console.Error.WriteLine($"Unknown request to {path}: {requestInfo}");
                        exitCode = 2; // Unexpected request
                        break;
                    }

                    expectedRequestCount--;
                    
                    var responseHeaders = new StringBuilder();
                    responseHeaders.Append("HTTP/1.1 200 OK\r\n");
                    responseHeaders.Append("Content-Type: application/json\r\n");
                    responseHeaders.Append("Content-Length: ");
                    responseHeaders.Append(responseHtml.Length.ToString());
                    responseHeaders.Append("\r\nConnection: close\r\n\r\n");

                    var fullResponse = responseHeaders.ToString() + responseHtml;
                    var responseBytes = Encoding.ASCII.GetBytes(fullResponse);

                    await client.GetNetworkStream().WriteAsync(responseBytes, 0, responseBytes.Length);
                    Console.WriteLine($"Sent response: HTTP 200 {responseHtml.Length} bytes");
                    
                    // Close and reuse the listener (but keep accepting)
                    await client.GetNetworkStream().ShutdownAsync(ShutdownState.ShutDown);
                }

                if (expectedRequestCount == 0 && receivedRequests.Count >= 2)
                {
                    Console.WriteLine("Mock provider completed successfully: all expected requests received");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Mock provider error: {ex.Message}");
                exitCode = 3; // Error
            }
            finally
            {
                timer.Stop();
                listener.Stop();
                cancellationTokenSource.Cancel();
                
                // Drain any remaining connections
                while (listener.Pending())
                {
                    try
                    {
                        var client = listener.AcceptTcpClient();
                        if (client.Connected)
                        {
                            client.GetNetworkStream().Shutdown(ShutdownState.ShutDown);
                            client.Close();
                        }
                    }
                    catch { break; }
                }

                Console.WriteLine($"Mock provider shutting down. Received {receivedRequests.Count} requests.");
            }
        }

        private static Dictionary<string, string> ParseFormData(string body)
        {
            var result = new Dictionary<string, string>();
            if (string.IsNullOrEmpty(body)) return result;

            foreach (var pair in System.Net.WebUtility.ParseQueryString(body))
            {
                result[pair.Key] = pair.Value;
            }

            // Handle multi-value form parameters that ParseQueryString may combine
            var pairs = body.Split('&');
            foreach (var pair in pairs)
            {
                var parts = pair.Split(new[] { '=' }, 2);
                if (parts.Length == 2)
                {
                    string key = System.Net.WebUtility.UrlDecode(parts[0]);
                    string value = System.Net.WebUtility.UrlDecode(parts[1]);
                    
                    // Only add if not already present (preserve first occurrence for duplicates)
                    if (!result.ContainsKey(key))
                    {
                        result[key] = value;
                    }
                }
            }

            return result;
        }
    }
}
