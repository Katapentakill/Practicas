using System.Security.Cryptography;
using System.Text;
using courses_dotnet_api.Src.DTOs;
using courses_dotnet_api.Src.Interfaces;
using courses_dotnet_api.Src.Models;
using Microsoft.EntityFrameworkCore;

namespace courses_dotnet_api.Src.Data;

public class AccountRepository : IAccountRepository
{
    private readonly DataContext _dataContext;

    public AccountRepository(DataContext dataContext)
    {
        _dataContext = dataContext;
    }

    public async Task<bool> SaveChangesAsync()
    {
        return 0 < await _dataContext.SaveChangesAsync();
    }

    public async Task AddAccountAsync(RegisterStudentDto registerStudentDto)
    {
        using var hmac = new HMACSHA512();

        Student student =
            new()
            {
                Rut = registerStudentDto.Rut,
                Name = registerStudentDto.Name,
                Email = registerStudentDto.Email,
                PasswordHash = hmac.ComputeHash(
                    Encoding.UTF8.GetBytes(registerStudentDto.Password)
                ),
                PasswordSalt = hmac.Key
            };

        await _dataContext.Students.AddAsync(student);
    }
    public async Task<bool> VerifyPassword(string password, string email)
    {
        Student? student = await _dataContext.Students.FirstOrDefaultAsync(s => s.Email == email);

        if(student is null)
            return false;
        
        byte[] storedHash = student.PasswordHash;
        byte[] salt = student.PasswordSalt;

        using (var hmac = new HMACSHA512(salt))
        {
            byte[] computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

            for(int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != storedHash[i])
                    return false;
            }
        }
        return true;
    }
}
