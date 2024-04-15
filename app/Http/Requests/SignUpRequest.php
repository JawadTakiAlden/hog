<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Factory;
use Illuminate\Validation\Rule;

class SignUpRequest extends FormRequest
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
            'device_id' => 'required|unique:users,device_id',
            'device_notification_id' => 'required'
        ];
    }

}
