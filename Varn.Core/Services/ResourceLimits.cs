namespace Varn.Core.Services;

/// <param name="MaxThreads">Сколько потоков разрешено занимать (с учётом внутреннего параллелизма алгоритма).</param>
/// <param name="MemoryFraction">Какую долю доступной памяти разрешено занимать (от 0,05 до 0,9).</param>
public sealed record ResourceLimits(int MaxThreads, double MemoryFraction)
{
    public const double DefaultMemoryFraction = 0.25;

    /// <summary>Половина логических потоков: оставляет запас для остальной системы.</summary>
    public static int DefaultThreads() => Math.Max(1, Environment.ProcessorCount / 2);

    public static ResourceLimits Default => new(DefaultThreads(), DefaultMemoryFraction);

    /// <summary>Приводит значения к допустимым диапазонам.</summary>
    public ResourceLimits Normalized() => new(
        Math.Clamp(MaxThreads, 1, Environment.ProcessorCount),
        Math.Clamp(MemoryFraction, 0.05, 0.9));
}