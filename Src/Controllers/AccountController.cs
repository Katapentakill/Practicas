using courses_dotnet_api.Src.DTOs;
using courses_dotnet_api.Src.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace courses_dotnet_api.Src.Controllers;

public class AccountController : BaseApiController
{
    private readonly IStudentRepository _studentRepository;
    private readonly IAccountRepository _accountRepository;
    private readonly ITokenService _tokenService;

    public AccountController(
        IStudentRepository studentRepository,
        IAccountRepository accountRepository,
        ITokenService tokenService
    )
    {
        _studentRepository = studentRepository;
        _accountRepository = accountRepository;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<IResult> Register(RegisterStudentDto registerStudentDto)
    {
        StudentDto? student = await _studentRepository.GetStudentByRutOrEmailAsync(
            registerStudentDto.Rut,
            registerStudentDto.Email
        );

        if (student is not null)
            return TypedResults.BadRequest("The user already exists");

        await _accountRepository.AddAccountAsync(registerStudentDto);

        bool saveChanges = await _studentRepository.SaveChangesAsync();

        if (!saveChanges)
            return TypedResults.BadRequest("An error ocurred while registering the account");

        AccountDto accountDto =
            new()
            {
                Rut = registerStudentDto.Rut,
                Name = registerStudentDto.Name,
                Email = registerStudentDto.Email,
                Token = _tokenService.CreateToken(registerStudentDto.Rut)
            };

        return TypedResults.Ok(accountDto);
    }
    [HttpPost("login")]
    public async Task<IResult> Login(LoginStudentDto loginStudentDto)
    {
        StudentDto? student = await _studentRepository.GetStudentByEmailAsync(
            loginStudentDto.Email
        );

        if (student is null)
            return TypedResults.BadRequest("Credentials are invalid");

        bool isPasswordValid = await _accountRepository.VerifyPassword(loginStudentDto.Password,student.Email);

        if (!isPasswordValid)
            return TypedResults.BadRequest("Credentials are invalid");
        
        string token = _tokenService.CreateToken(student.Rut);
        AccountDto accountDto =
            new()
            {
                Rut = student.Rut,
                Name = student.Name,
                Email = loginStudentDto.Email,
                Token = _tokenService.CreateToken(student.Rut)
            }; 
        
        return TypedResults.Ok(accountDto);
    }
}
