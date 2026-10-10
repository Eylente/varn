using ClosedXML.Excel;
using Varn.Core.Models;

namespace Varn.Core.Services;

public class ExcelService
{
    public void CreateTemplate(string filePath)
    {
        using var workbook = new XLWorkbook();
        var worksheet = workbook.Worksheets.Add("Users");
        worksheet.Cell(1, 1).Value = "Login";
        worksheet.Cell(1, 2).Value = "Password";
        worksheet.Columns().AdjustToContents();
        workbook.SaveAs(filePath);
    }

    public List<UserInput> ReadEmployees(string filePath)
    {
        var users = new List<UserInput>();
        using var workbook = new XLWorkbook(filePath);
        var worksheet = workbook.Worksheet(1);
        var rows = worksheet.RangeUsed()?.RowsUsed().Skip(1) ?? Enumerable.Empty<IXLRangeRow>();

        foreach (var row in rows)
        {
            users.Add(new UserInput(
                row.Cell(1).GetString(),
                row.Cell(2).GetString()));
        }

        return users;
    }

    public void SaveResults(string filePath, IReadOnlyList<UserOutput> results)
    {
        using var workbook = new XLWorkbook();
        var worksheet = workbook.Worksheets.Add("Hashed Data");

        worksheet.Cell(1, 1).Value = "Login";
        worksheet.Cell(1, 2).Value = "Password Hash";
        worksheet.Cell(1, 3).Value = "Salt";
        worksheet.Cell(1, 4).Value = "Algorithm";
        worksheet.Cell(1, 5).Value = "Parameters";
        worksheet.Cell(1, 6).Value = "Note";

        for (int i = 0; i < results.Count; i++)
        {
            worksheet.Cell(i + 2, 1).Value = results[i].Login;
            worksheet.Cell(i + 2, 2).Value = results[i].PasswordHash;
            worksheet.Cell(i + 2, 3).Value = results[i].Salt;
            worksheet.Cell(i + 2, 4).Value = results[i].Algorithm;
            worksheet.Cell(i + 2, 5).Value = results[i].Parameters;
            worksheet.Cell(i + 2, 6).Value = results[i].Note;
        }

        worksheet.Columns().AdjustToContents();
        workbook.SaveAs(filePath);
    }

    public bool IsTemplateValid(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath) || new FileInfo(filePath).Length < 100)
        {
            return false;
        }

        try
        {
            using var workbook = new XLWorkbook(filePath);
            var worksheet = workbook.Worksheet(1);
            if (worksheet == null) return false;

            string col1 = worksheet.Cell(1, 1).GetString().Trim();
            string col2 = worksheet.Cell(1, 2).GetString().Trim();

            return col1.Equals("Login", StringComparison.OrdinalIgnoreCase) &&
                   col2.Equals("Password", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }
}