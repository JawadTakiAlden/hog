<?php

namespace App\Http\Requests;

use App\Types\UserType;
use Illuminate\Foundation\Http\FormRequest;

class CreateUserRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'full_name' => 'required|string|min:4',
            'phone' => 'required|min:10|max:10|unique:users,phone',
            'password' => 'required|min:7|max:26',
            'image' => 'image|mimes:png,jpg,jpeg|max:5120',
            'type' => 'required|in:teacher,admin,student,employee'
        ];
    }
}
