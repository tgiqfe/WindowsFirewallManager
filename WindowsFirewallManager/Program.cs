
using System.Text.Json;
using WindowsFirewallManager.WindowsFirewall;

var ruleItems = FirewallRuleItem.Load();
var ruleSummaries = FirewallRuleSummary.Load();

Console.WriteLine("Firewall Rules:");
foreach (var rule in ruleSummaries)
{
    Console.WriteLine($"- Name: {rule.DisplayName}, Direction: {rule.Direction}, Enabled: {rule.Enabled}, Action: {rule.ActionType}");
}

string json = JsonSerializer.Serialize(ruleItems, new JsonSerializerOptions
{
    WriteIndented = true,
    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    IgnoreReadOnlyProperties = true,
    Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    PropertyNameCaseInsensitive = true,
});
Console.WriteLine("\nFirewall Rule Items (JSON):");
Console.WriteLine(json);

Console.ReadLine();
