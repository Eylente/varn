using Varn.Core.Models;
using Varn.Core.Services;
using System;
using System.Collections.Generic;
using System.Text;

namespace Varn.Core.Tests
{
    public class ExcelServiceTests : IDisposable
    {
        private readonly ExcelService _excelService;
        private readonly string _tempFilePath;

        public ExcelServiceTests()
        {
            _excelService = new ExcelService();
            _tempFilePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.xlsx");
        }

        public void Dispose()
        {
            if (File.Exists(_tempFilePath))
            {
                File.Delete(_tempFilePath);
            }
        }

        [Fact]
        public void CreateTemplate_ShouldCreateValidTemplateFile()
        {
            // Act
            _excelService.CreateTemplate(_tempFilePath);

            // Assert
            Assert.True(File.Exists(_tempFilePath));
            Assert.True(_excelService.IsTemplateValid(_tempFilePath));
        }

        [Fact]
        public void SaveAndReadEmployees_ShouldMatchData()
        {
            _excelService.CreateTemplate(_tempFilePath);

            // Act
            var expectedOutputs = new List<UserOutput>
            {
                new UserOutput("admin", "hash123", "salt123", "Argon2id"),
                new UserOutput("user_test", "hash456", "salt456", "BCrypt")
            };
            _excelService.SaveResults(_tempFilePath, expectedOutputs);

            var actualInputs = _excelService.ReadEmployees(_tempFilePath);

            // Assert
            Assert.NotNull(actualInputs);
            Assert.Equal(2, actualInputs.Count);
            Assert.Equal("admin", actualInputs[0].Login);
            Assert.Equal("hash123", actualInputs[0].Password);
            Assert.Equal("user_test", actualInputs[1].Login);
        }

        [Fact]
        public void IsTemplateValid_WithInvalidFile_ShouldReturnFalse()
        {
            // Act
            bool isValid = _excelService.IsTemplateValid("non_existent_file.xlsx");

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void IsTemplateValid_WithCorruptedOrWrongExtensionFile_ShouldReturnFalse()
        {
            // Arrange:
            string badFilePath = Path.Combine(Path.GetTempPath(), "fake_excel.xlsx");
            File.WriteAllText(badFilePath, "Это просто текст, а не структура zip/xml от Excel");

            try
            {
                // Act
                bool isValid = _excelService.IsTemplateValid(badFilePath);

                // Assert
                Assert.False(isValid, "Метод должен возвращать false, если файл поврежден или имеет неверный формат");
            }
            finally
            {
                if (File.Exists(badFilePath)) File.Delete(badFilePath);
            }
        }

        [Fact]
        public void ReadEmployees_WithEmptyCells_ShouldHandleGracefully()
        {
            // Arrange:
            _excelService.CreateTemplate(_tempFilePath);

            var brokenData = new List<UserOutput>
            {
                new UserOutput("user_without_password", "", null, "Argon2id")
            };
            _excelService.SaveResults(_tempFilePath, brokenData);

            // Act
            var results = _excelService.ReadEmployees(_tempFilePath);

            // Assert
            Assert.NotNull(results);
            Assert.Single(results);
            Assert.Equal("user_without_password", results[0].Login);

            Assert.True(results[0].Password == "" || results[0].Password == null);
        }
    }
}