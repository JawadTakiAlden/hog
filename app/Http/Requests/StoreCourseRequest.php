<?php

namespace App\Http\Requests;

use App\Types\UserType;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreCourseRequest extends FormRequest
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
            'name' => 'required|string',
            'image' => 'required|mimes:jpg,png,jpeg|max:4096',
            'is_visible' => 'required|boolean',
            'is_open' => 'required|boolean',
            'categories' => 'required|array',
            'categories.*' => ['numeric' , Rule::exists('categories' , 'id')],
            'teachers' =>  'required|array',
            'teachers.*' => ['numeric' , Rule::exists('users' , 'id')],
            'values' => 'array',
            'values.*' => 'string|max:255',
            'telegram_channel_link' => 'string'
        ];
    }
}
