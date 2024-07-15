<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\SignupRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Response;

class AuthController extends Controller
{
    public function signup(SignupRequest $request)
    {
        $data = $request->validated();

        // Create a new user
        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
        ]);

        // Create token for the user
        $token = $user->createToken('main')->plainTextToken;

        // Return user and token
        return response()->json(compact('user', 'token'));
    }

    public function login(LoginRequest $request)
    {
        $credentials = $request->validated();
        // Attempt to authenticate user
        if (!Auth::attempt($credentials)) {
            Log::info('Failed login attempt', ['email' => $credentials['email']]);
            return response()->json([
                'message' => 'Provided email or password is incorrect'
            ], 422);
        }

        // Retrieve authenticated user and create token
        $user = Auth::user();
        $token = $user->createToken('main')->plainTextToken;

        // Return user and token
        return response()->json(compact('user', 'token'));
    }

    public function logout(Request $request)
    {
        // Delete the user's current access token
        $user = $request->user();
        $user->currentAccessToken()->delete();

        // Return success response
        return response()->json([], 204);
    }
}