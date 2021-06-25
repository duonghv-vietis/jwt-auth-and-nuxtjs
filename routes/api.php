<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

Route::group(['prefix' => 'auth', ['middleware' => 'throttle:20,5']], function () {
    Route::post('/register', 'Api\Auth\RegisterController@register');
    Route::post('/login', 'Api\Auth\LoginController@login');
});

Route::group(['middleware' => 'jwt.auth'], function (){
    Route::get('/me', 'Api\MeController@index');
    Route::get('/auth/logout', 'Api\MeController@logout');
});