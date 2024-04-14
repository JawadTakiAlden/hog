<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateCourseRequest extends FormRequest
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
            'name' => 'string',
            'image' => 'mimes:jpg,png,jpeg|max:4096',
            'telegram_channel_link' => 'string',
            'is_visible' => 'boolean',
            'is_open' => 'boolean',
            'categories' => 'array',
            'categories.*' => ['numeric' , Rule::exists('categories' , 'id')],
            'teachers' => 'array',
            'teachers.*' => ['numeric' , Rule::exists('users' , 'id')],
        ];
    }
}
