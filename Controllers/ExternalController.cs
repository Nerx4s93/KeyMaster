using KeyMaster.Models;
using KeyMaster.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace KeyMaster.Controllers;

[ApiController]
[Route("api/external")]
public class ExternalController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IApiKeyEncryptor _encryptor;

    public ExternalController(
        AppDbContext db,
        IApiKeyEncryptor encryptor)
    {
        _db = db;
        _encryptor = encryptor;
    }

    [HttpGet("keys")]
    public async Task<IActionResult> GetAll()
    {
        var user = await GetUser();

        if (user is null)
        {
            return Unauthorized();
        }

        var keys = await _db.Keys
            .AsNoTracking()
            .Where(x => x.UserId == user.Id)
            .OrderBy(x => x.Name)
            .ToListAsync();

        return Ok(keys.Select(x => new
        {
            x.Id,
            x.Name,
            x.Description,
            Key = _encryptor.Decrypt(x.Key)
        }));
    }

    [HttpGet("keys/{id:int}")]
    public async Task<IActionResult> GetById(int id)
    {
        var user = await GetUser();

        if (user is null)
        {
            return Unauthorized();
        }

        var key = await _db.Keys
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.Id == id && x.UserId == user.Id);

        if (key is null)
        {
            return NotFound("Ключ не найден.");
        }

        return Ok(new
        {
            key.Id,
            key.Name,
            key.Description,
            Key = _encryptor.Decrypt(key.Key)
        });
    }

    private async Task<User?> GetUser()
    {
        var rawMasterKey = Request.Headers["X-Master-Key"].FirstOrDefault();

        if (string.IsNullOrWhiteSpace(rawMasterKey))
        {
            return null;
        }

        var hash = UserController.Hash(rawMasterKey);

        return await _db.Users
            .SingleOrDefaultAsync(x => x.CentralApiKeyHash == hash);
    }
}
