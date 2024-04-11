using courses_dotnet_api.Src.DTOs;

namespace courses_dotnet_api.Src.Interfaces;

public interface IAccountRepository
{
    Task<bool> SaveChangesAsync();
    Task AddAccountAsync(RegisterStudentDto registerStudentDto);
    Task<bool> VerifyPassword(string password, string email);
}
