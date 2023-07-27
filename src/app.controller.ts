import { Controller, Get, Header } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiExcludeEndpoint } from '@nestjs/swagger';
import { readFile } from 'fs/promises';

@Controller()
export class AppController {
    constructor(private readonly appService: AppService) { }

    @ApiExcludeEndpoint()
    @Get()
    getHello(): string {
        return this.appService.getIndex();
    }

    @Get('docs/swagger.css')
    @Header('Content-Type', 'text/css')
    @ApiExcludeEndpoint()
    getSwaggerCSS() {
        return readFile('./public/swagger.css', 'utf-8');
    }
}