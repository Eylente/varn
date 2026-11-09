using System;
using System.Collections.Generic;
using System.Linq;

namespace Varn.Desktop.Localization;

public static class CoreMessages
{
    public static string Translate(string? code, string? english, IReadOnlyList<string>? arguments = null)
    {
        if (string.IsNullOrEmpty(code)) return english ?? string.Empty;

        string key = "Msg_" + code;
        string template = Loc.Instance[key];
        if (template == key) return english ?? string.Empty;

        object[] values = arguments is null ? [] : arguments.Cast<object>().ToArray();
        try
        {
            return string.Format(template, values);
        }
        catch (FormatException)
        {
            return english ?? template;
        }
    }

    public static string FromException(Exception exception)
    {
        if (exception.Data["code"] is not string code) return exception.Message;

        var arguments = new List<string>();
        int index = 0;
        while (exception.Data[$"arg{index}"] is string argument)
        {
            arguments.Add(argument);
            index++;
        }

        return Translate(code, exception.Message, arguments);
    }
}