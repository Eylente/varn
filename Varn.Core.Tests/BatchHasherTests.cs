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
    
    [Fact]
    public void RecommendedParallelism_RespectsThreadLimit()
    {
        var limits = new ResourceLimits(MaxThreads: 2, MemoryFraction: 0.5);

        int result = BatchHasher.RecommendedParallelism(1, 1, limits);

        Assert.InRange(result, 1, Math.Min(2, Environment.ProcessorCount));
    }

    [Fact]
    public void RecommendedParallelism_CountsInternalThreads()
    {
        var limits = new ResourceLimits(MaxThreads: Environment.ProcessorCount, MemoryFraction: 0.9);

        int result = BatchHasher.RecommendedParallelism(1, internalThreads: 4, limits);

        Assert.True(result <= Math.Max(1, Environment.ProcessorCount / 4));
        Assert.True(result >= 1);
    }

    [Fact]
    public void RecommendedParallelism_HugeMemoryPerHash_ReturnsOne() =>
        Assert.Equal(1, BatchHasher.RecommendedParallelism(long.MaxValue / 2, 1, ResourceLimits.Default));

    [Fact]
    public void ResourceLimits_Normalized_ClampsValues()
    {
        var low = new ResourceLimits(0, -1).Normalized();
        var high = new ResourceLimits(100_000, 5).Normalized();

        Assert.Equal(1, low.MaxThreads);
        Assert.Equal(0.05, low.MemoryFraction);
        Assert.Equal(Environment.ProcessorCount, high.MaxThreads);
        Assert.Equal(0.9, high.MemoryFraction);
    }

    [Fact]
    public void ResourceLimits_Default_IsHalfOfThreads()
    {
        var limits = ResourceLimits.Default;

        Assert.Equal(Math.Max(1, Environment.ProcessorCount / 2), limits.MaxThreads);
        Assert.Equal(0.25, limits.MemoryFraction);
    }
}