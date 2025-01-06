import {
  Controller,
  Get,
  Post,
  Body,
  Put,
  Param,
  Delete,
  UseGuards,
  Headers,
  Query,
  NotFoundException,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiTags,
  ApiOperation,
  //ApiHeader,
  ApiResponse,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { AuthService } from '../auth.service';
import { UserRole, UserStatus } from '../schemas/user.schema';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { Roles } from '../decorators/roles.decorator';
import { CreateEmployeeDto } from '../dto/create-employee.dto';
import { createSuccessResponse } from 'src/ApiRespose/interface/response.interface';
import { EmployeeFilterDto } from '../dto/employee-filter.dto';

@ApiTags('Admin - Employees')
@Controller('admin/employees')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.ADMIN)
@ApiBearerAuth('access-token') // Must match the name in main.ts
// @ApiHeader({
//   name: 'Authorization',
//   description: 'Bearer <JWT token>',
//   required: true,
// })
export class AdminEmployeeController {
  constructor(private readonly authService: AuthService) {}

  @Get('validate-token')
  @ApiOperation({ summary: 'Validate JWT token' })
  async validateToken(@Headers('authorization') auth: string) {
    console.log('Auth header:', auth);
    return {
      valid: true,
      token: auth?.replace('Bearer ', ''),
    };
  }

  @Post()
  @ApiOperation({ summary: 'Create new employee' })
  @ApiResponse({ status: 201, description: 'Employee successfully created.' })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({ status: 403, description: 'Forbidden - Requires Admin Role.' })
  async createEmployee(@Body() employeeData: CreateEmployeeDto) {
    return this.authService.createEmployee({
      ...employeeData,
      role: UserRole.EMPLOYEE,
      status: UserStatus.ACTIVE,
    });
  }

  @Get()
  @ApiOperation({ summary: 'Get all employees with pagination and filters' })
  @ApiResponse({
    status: 200,
    description: 'Returns filtered and paginated list of employees',
  })
  @ApiQuery({ name: 'search', required: false, type: String })
  @ApiQuery({ name: 'status', required: false, enum: UserStatus })
  @ApiQuery({
    name: 'sortBy',
    required: false,
    enum: ['createdAt', 'username', 'email', 'fullName'],
  })
  @ApiQuery({ name: 'sortOrder', required: false, enum: ['asc', 'desc'] })
  async findAll(@Query() filterDto: EmployeeFilterDto) {
    const result = await this.authService.findAllEmployees(filterDto);
    return createSuccessResponse(result);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get employee by ID' })
  @ApiParam({ name: 'id', description: 'Employee ID' })
  @ApiResponse({
    status: 200,
    description: 'Employee found successfully',
  })
  @ApiResponse({
    status: 404,
    description: 'Employee not found',
  })
  async getEmployee(@Param('id') id: string) {
    const employee = await this.authService.findEmployeeById(id);
    if (!employee) {
      throw new NotFoundException(`Employee with ID ${id} not found`);
    }
    return {
      success: true,
      data: {
        id: employee._id,
        username: employee.username,
        email: employee.email,
        fullName: employee.fullName,
        phone: employee.phone,
        status: employee.status,
      },
    };
  }

  @Put(':id')
  async updateEmployee(@Param('id') id: string, @Body() updateData: any) {
    return this.authService.updateEmployee(id, updateData);
  }

  @Delete(':id')
  async deleteEmployee(@Param('id') id: string) {
    return this.authService.deleteEmployee(id);
  }
}
