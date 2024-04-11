using System.Security.Cryptography;
using System.Text;
using AutoMapper;
using courses_dotnet_api.Src.DTOs;
using courses_dotnet_api.Src.Interfaces;
using courses_dotnet_api.Src.Models;
using Microsoft.EntityFrameworkCore;

namespace courses_dotnet_api.Src.Data;

public class StudentRepository : IStudentRepository
{
    private readonly DataContext _dataContext;
    private readonly IMapper _mapper;

    public StudentRepository(DataContext dataContext, IMapper mapper)
    {
        _dataContext = dataContext;
        _mapper = mapper;
    }

    public async Task<bool> SaveChangesAsync()
    {
        return 0 < await _dataContext.SaveChangesAsync();
    }

    public async Task AddStudentAsync(CreateStudentDto createStudentDto)
    {
        Student student = _mapper.Map<Student>(createStudentDto);
        await _dataContext.Students.AddAsync(student);
    }

    public async Task<StudentDto?> GetStudentByIdAsync(int id)
    {
        Student? student = await _dataContext.Students.FindAsync(id);
        return _mapper.Map<StudentDto>(student);
    }

    public async Task<StudentDto?> GetStudentByRutAsync(string rut)
    {
        Student? student = await _dataContext.Students.FirstOrDefaultAsync(s => s.Rut == rut);
        return _mapper.Map<StudentDto>(student);
    }

    public async Task<StudentDto?> GetStudentByEmailAsync(string email)
    {
        Student? student = await _dataContext.Students.FirstOrDefaultAsync(s => s.Email == email);
        return _mapper.Map<StudentDto>(student);
    }

    public async Task<StudentDto?> GetStudentByRutOrEmailAsync(string rut, string email)
    {
        Student? student = await _dataContext.Students.FirstOrDefaultAsync(s =>
            s.Rut == rut || s.Email == email
        );
        return _mapper.Map<StudentDto>(student);
    }

    public async Task<IEnumerable<StudentDto>> GetStudentsAsync()
    {
        IEnumerable<Student> students = await _dataContext.Students.ToListAsync();
        return _mapper.Map<IEnumerable<StudentDto>>(students);
    }

    public async Task<bool> UpdateStudentByIdAsync(int id, UpdateStudentDto updateStudentDto)
    {
        Student? student = await _dataContext.Students.FindAsync(id);

        if (student is null)
            return false;

        _mapper.Map(updateStudentDto, student);

        return true;
    }

    public async Task<bool> DeleteStudentByIdAsync(int id)
    {
        Student? student = await _dataContext.Students.FindAsync(id);

        if (student is null)
            return false;

        _dataContext.Students.Remove(student);

        return true;
    }
}
