using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Varn.Core.Models
{
    public record UserOutput(
        string Login,
        string PasswordHash,
        string? Salt,
        string Algorithm,
        string? Parameters = null,
        string? Note = null
    );
}