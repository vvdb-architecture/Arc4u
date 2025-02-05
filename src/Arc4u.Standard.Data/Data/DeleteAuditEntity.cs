using System.Runtime.Serialization;

namespace Arc4u.Data;

/// <summary>
/// Represents a <see cref="PersistEntity"/> 
/// identified with a <see cref="System.Guid"/>,
/// auditing its creation, update and delete information with <see cref="System.string"/> and <see cref="System.DateTimeOffset"/>.
/// </summary>
/// <remarks>Storage members are marked as protected in order to enable LinqToSql mappings.</remarks>

[DataContract]
public class DeleteAuditEntity : DeleteAuditEntity<Guid, string, DateTimeOffset, string, DateTimeOffset?, string, DateTimeOffset?>
{
    #region Constructors

    /// <summary>
    /// Initializes a new instance of the <see cref="DeleteAuditEntity"/> class 
    /// <see cref="PersistChange"/> is defaulted to None.
    /// </summary>
    public DeleteAuditEntity() : this(PersistChange.None)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DeleteAuditEntity"/> class 
    /// with the specified <see cref="PersistChange"/> 
    /// </summary>
    /// <param name="persistChange">The persist change.</param>
    public DeleteAuditEntity(PersistChange persistChange) : base(persistChange)
    {
        Id = Guid.NewGuid();
        CreatedOn = DateTimeOffset.UtcNow;
    }

    #endregion
}
