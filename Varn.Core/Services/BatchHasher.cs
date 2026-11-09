using Varn.Core.Models;
using Varn.Core.Security.Interfaces;
using Varn.Core.Security.Models;

namespace Varn.Core.Services;

public sealed class BatchHasher
{
    /// <summary>Сколько памяти один хэш занимает одновременно (для ограничения параллелизма).</summary>
    public static long EstimateMemoryPerHashBytes(PasswordAlgorithm algorithm, HasherSettings settings) =>
        algorithm switch
        {
            PasswordAlgorithm.Argon2id => (long)settings.Argon2.MemoryKb * 1024,
            PasswordAlgorithm.Scrypt => 128L * settings.Scrypt.CostFactor * settings.Scrypt.BlockSize,
            _ => 1024 * 1024
        };

    /// <summary>Память, которую процесс вообще может использовать (физическая или лимит контейнера).</summary>
    public static long AvailableMemoryBytes() => GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;

    /// <summary>Сколько потоков использует один хэш внутри: у Argon2 это параметр параллелизма.</summary>
    public static int EstimateInternalThreads(PasswordAlgorithm algorithm, HasherSettings settings) =>
        algorithm == PasswordAlgorithm.Argon2id ? Math.Max(1, settings.Argon2.Parallelism) : 1;

    /// <summary>Сколько хэшей считать одновременно, не выходя за лимиты потоков и памяти (минимум один).</summary>
    public static int RecommendedParallelism(long memoryPerHashBytes, int internalThreads, ResourceLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);

        limits = limits.Normalized();
        internalThreads = Math.Max(1, internalThreads);

        int byThreads = Math.Max(1, limits.MaxThreads / internalThreads);

        long budget = (long)(AvailableMemoryBytes() * limits.MemoryFraction);
        long byMemory = memoryPerHashBytes <= 0 ? int.MaxValue : Math.Max(1, budget / memoryPerHashBytes);

        return (int)Math.Min(byThreads, byMemory);
    }

    /// <summary>Короткая форма с лимитами по умолчанию.</summary>
    public static int RecommendedParallelism(long memoryPerHashBytes) =>
        RecommendedParallelism(memoryPerHashBytes, 1, ResourceLimits.Default);

    public IReadOnlyList<UserOutput> HashAll(
        IReadOnlyList<UserInput> users,
        IPasswordHasher hasher,
        int maxDegreeOfParallelism,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(users);
        ArgumentNullException.ThrowIfNull(hasher);

        var results = new UserOutput[users.Count];
        int processed = 0;
        int lastReportedPercent = -1;

        var options = new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Max(1, maxDegreeOfParallelism),
            CancellationToken = cancellationToken
        };

        Parallel.For(0, users.Count, options, i =>
        {
            results[i] = HashOne(users[i], hasher);

            int done = Interlocked.Increment(ref processed);
            if (progress is null) return;

            // Прогресс сообщаем только когда процент вырос, без блокировок на каждую строку
            int percent = (int)(done * 100L / users.Count);
            int previous = Volatile.Read(ref lastReportedPercent);
            if (percent > previous &&
                Interlocked.CompareExchange(ref lastReportedPercent, percent, previous) == previous)
            {
                progress.Report(percent);
            }
        });

        return results;
    }

    private static UserOutput HashOne(UserInput user, IPasswordHasher hasher)
    {
        if (string.IsNullOrEmpty(user.Password))
            return new UserOutput(user.Login, "", null, hasher.AlgorithmName, null, "Empty password");

        try
        {
            var r = hasher.Hash(user.Password);
            return new UserOutput(user.Login, r.Hash, r.Salt, r.Algorithm, r.ParametersJson, r.Warning);
        }
        catch (Exception ex)
        {
            return new UserOutput(user.Login, "", null, hasher.AlgorithmName, null, $"Error: {ex.Message}");
        }
    }
}