using System.Collections.Concurrent;
using Varn.Core.Models;
using Varn.Core.Security.Models;
using Varn.Core.Security.Services;
using Varn.Core.Services;

namespace Varn.Core.Tests;

public class BatchHasherTests
{
    private static readonly Varn.Core.Security.Interfaces.IPasswordHasher Fast =
        PasswordHasherFactory.Create(
            PasswordAlgorithm.Pbkdf2,
            new HasherSettings { Pbkdf2Iterations = 1000 });

    private sealed class SyncProgress(Action<int> onReport) : IProgress<int>
    {
        public void Report(int value) => onReport(value);
    }

    [Fact]
    public void HashAll_KeepsOrder_AndMarksEmptyPassword()
    {
        var users = new List<UserInput> { new("a", "p1"), new("b", ""), new("c", "p3") };

        var results = new BatchHasher().HashAll(users, Fast, maxDegreeOfParallelism: 2);

        Assert.Equal(new[] { "a", "b", "c" }, results.Select(r => r.Login));
        Assert.Null(results[0].Note);
        Assert.NotEmpty(results[0].PasswordHash);
        Assert.NotNull(results[1].Note);
        Assert.Equal("", results[1].PasswordHash);
    }

    [Fact]
    public void HashAll_ReportsProgressUpTo100()
    {
        var users = Enumerable.Range(0, 20).Select(i => new UserInput($"u{i}", "pw")).ToList();
        var reported = new ConcurrentBag<int>();

        new BatchHasher().HashAll(users, Fast, 4, new SyncProgress(reported.Add));

        Assert.Contains(100, reported);
    }

    [Fact]
    public void RecommendedParallelism_IsAtLeastOne_AndNotAboveCpuCount()
    {
        int huge = BatchHasher.RecommendedParallelism(long.MaxValue / 2);
        int tiny = BatchHasher.RecommendedParallelism(1);

        Assert.Equal(1, huge);
        Assert.InRange(tiny, 1, Environment.ProcessorCount);
    }
}