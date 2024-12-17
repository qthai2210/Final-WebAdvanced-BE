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
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiTags,
  ApiOperation,
  //ApiHeader,
  ApiResponse,
} from '@nestjs/swagger';
import { AuthService } from '../auth.service';
import { UserRole, UserStatus } from '../schemas/user.schema';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { Roles } from '../decorators/roles.decorator';
import { CreateEmployeeDto } from '../dto/create-employee.dto';

@Controller('admin/employees')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.ADMIN)
@ApiTags('Employee Management')
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
  @ApiOperation({ summary: 'Get all employees' })
  @ApiResponse({ status: 200, description: 'List of all employees.' })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  @ApiResponse({ status: 403, description: 'Forbidden - Requires Admin Role.' })
  async getAllEmployees() {
    console.log('get all employees');
    // log access token
    return this.authService.findAllEmployees();
  }

  @Get(':id')
  async getEmployee(@Param('id') id: string) {
    return this.authService.findEmployeeById(id);
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
