<?php

namespace App\Http\Requests;

use App\Types\LesionType;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateLesionRequest extends FormRequest
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
            'videoURI' => 'string|max:255',
            'pdfFile' => 'file|max:10240',
            'is_visible' => 'required|boolean',
            'is_open' => 'required|boolean',
            'title' => 'nullable|string|max:255',
            'type' => 'string|in:'.implode(',',[LesionType::VIDEO , LesionType::PDF]),
            'time' => 'required_if:type,'.LesionType::PDF,
            'description' => 'nullable|string'
        ];
    }
}
