import { Controller, Get, Header } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { AppService } from './app.service';
import { ApiExcludeEndpoint } from '@nestjs/swagger';
import { readFile } from 'fs/promises';

@Controller()
export class AppController {
    constructor(private readonly appService: AppService) {}

    @ApiExcludeEndpoint()
    @Get()
    @SkipThrottle()
    getIndex(): string {
        return this.appService.getIndex();
    }

    @Get('docs/swagger.css')
    @Header('Content-Type', 'text/css')
    @ApiExcludeEndpoint()
    @SkipThrottle()
    getSwaggerCSS() {
        return readFile('./public/swagger.css', 'utf-8');
    }
}
