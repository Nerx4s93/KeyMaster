using KeyMaster.Models;
using KeyMaster.Models.API;
using KeyMaster.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace KeyMaster.Controllers;

[ApiController]
[Authorize]
[Route("api/keys")]
public class ApiKeysController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IApiKeyEncryptor _encryptor;

    public ApiKeysController(
        AppDbContext db,
        IApiKeyEncryptor encryptor)
    {
        _db = db;
        _encryptor = encryptor;
    }

    [HttpPost("create")]
    public async Task<ActionResult<ApiKeyResponse>> Create(
        CreateApiKeyRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest("Имя ключа обязательно.");
        }

        if (string.IsNullOrWhiteSpace(request.Key))
        {
            return BadRequest("API-ключ обязателен.");
        }

        var userId = GetUserId();

        if (userId is null)
        {
            return Unauthorized();
        }

        var apiKey = new APIKey
        {
            Name = request.Name.Trim(),
            Description = request.Description?.Trim() ?? string.Empty,
            Key = _encryptor.Encrypt(request.Key.Trim()),
            UserId = userId.Value
        };

        _db.Keys.Add(apiKey);

        await _db.SaveChangesAsync(cancellationToken);

        var response = new ApiKeyResponse(
            apiKey.Id,
            apiKey.Name,
            apiKey.Description,
            request.Key.Trim());

        return CreatedAtAction(
            nameof(GetById),
            new { id = apiKey.Id },
            response);
    }

    [HttpGet("get-all")]
    public async Task<ActionResult<IReadOnlyList<ApiKeyResponse>>> GetAll(
        CancellationToken cancellationToken)
    {
        var userId = GetUserId();

        if (userId is null)
        {
            return Unauthorized();
        }

        var keys = await _db.Keys
            .AsNoTracking()
            .Where(key => key.UserId == userId.Value)
            .OrderBy(key => key.Name)
            .ToListAsync(cancellationToken);

        var response = keys
            .Select(key => new ApiKeyResponse(
                key.Id,
                key.Name,
                key.Description,
                _encryptor.Decrypt(key.Key)))
            .ToList();

        return Ok(response);
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<ApiKeyResponse>> GetById(
        int id,
        CancellationToken cancellationToken)
    {
        var userId = GetUserId();

        if (userId is null)
        {
            return Unauthorized();
        }

        var apiKey = await _db.Keys
            .AsNoTracking()
            .SingleOrDefaultAsync(
                key =>
                    key.Id == id &&
                    key.UserId == userId.Value,
                cancellationToken);

        if (apiKey is null)
        {
            return NotFound("Ключ не найден.");
        }

        return Ok(new ApiKeyResponse(
            apiKey.Id,
            apiKey.Name,
            apiKey.Description,
            _encryptor.Decrypt(apiKey.Key)));
    }

    [HttpPatch("{id:int}")]
    public async Task<ActionResult<ApiKeyResponse>> Update(
        int id,
        UpdateApiKeyRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest("Имя ключа обязательно.");
        }

        if (string.IsNullOrWhiteSpace(request.Key))
        {
            return BadRequest("API-ключ обязателен.");
        }

        var userId = GetUserId();

        if (userId is null)
        {
            return Unauthorized();
        }

        var apiKey = await _db.Keys
            .SingleOrDefaultAsync(
                key =>
                    key.Id == id &&
                    key.UserId == userId.Value,
                cancellationToken);

        if (apiKey is null)
        {
            return NotFound("Ключ не найден.");
        }

        apiKey.Name = request.Name.Trim();
        apiKey.Description =
            request.Description?.Trim() ?? string.Empty;
        apiKey.Key = _encryptor.Encrypt(request.Key.Trim());

        await _db.SaveChangesAsync(cancellationToken);

        return Ok(new ApiKeyResponse(
            apiKey.Id,
            apiKey.Name,
            apiKey.Description,
            request.Key.Trim()));
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(
        int id,
        CancellationToken cancellationToken)
    {
        var userId = GetUserId();

        if (userId is null)
        {
            return Unauthorized();
        }

        var apiKey = await _db.Keys
            .SingleOrDefaultAsync(
                key =>
                    key.Id == id &&
                    key.UserId == userId.Value,
                cancellationToken);

        if (apiKey is null)
        {
            return NotFound("Ключ не найден.");
        }

        _db.Keys.Remove(apiKey);

        await _db.SaveChangesAsync(cancellationToken);

        return NoContent();
    }

    private int? GetUserId()
    {
        var userIdValue = User.FindFirstValue(
            ClaimTypes.NameIdentifier);

        return int.TryParse(userIdValue, out var userId)
            ? userId
            : null;
    }
}