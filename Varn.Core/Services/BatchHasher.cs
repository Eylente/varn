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

    /// <summary>Не больше числа ядер и не больше половины доступной процессу памяти.</summary>
    public static int RecommendedParallelism(long memoryPerHashBytes)
    {
        int cpu = Environment.ProcessorCount;
        if (memoryPerHashBytes <= 0) return cpu;

        long budget = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / 2;
        long byMemory = budget / memoryPerHashBytes;
        return (int)Math.Clamp(byMemory, 1, cpu);
    }

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