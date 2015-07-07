using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth0.ClaimsProvider.LogsProcessor
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("\n Auth0 Claims Provider Logs on {0}\n\n", Environment.MachineName);

            using (var session = new TraceEventSession("Auth0.ClaimsProvider.LogsProcessor"))
            {
                session.Source.Dynamic.All += delegate(TraceEvent data)
                {
                    if (!String.IsNullOrEmpty(data.FormattedMessage))
                    {
                        // Get the process name.
                        var processName = "Unknown process";
                        try
                        {
                            var process = Process.GetProcessById(data.ProcessID);
                            if (process != null)
                            {
                                processName = process.ProcessName;
                                process.Dispose();
                            }
                        }
                        catch (Exception)
                        {

                        }

                        // Display the process.
                        Console.WriteLine(" {0} - {1} [{2}]", data.TimeStamp.ToString("HH:mm:ss"), data.FormattedMessage, processName);
                    }
                };

                session.EnableProvider(
                    TraceEventProviders.GetEventSourceGuidFromName("Auth0-ClaimsProviderEventSource"));
                session.Source.Process();
            }

            Console.ReadLine();
        }
    }
}
