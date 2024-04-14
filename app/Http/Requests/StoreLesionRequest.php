<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreLesionRequest extends FormRequest
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
            'videoURI' => 'required_without:pdfFile|string|max:255',
            'pdfFile' => 'required_without:videoURI|file|max:10240',
            'is_visible' => 'required|boolean',
            'is_open' => 'required|boolean',
            'type' => 'required|in:pdf,video',
            'title' => 'nullable|string|max:255',
            'chapter_id' => ['required' , Rule::exists('chapters' , 'id')],
        ];
    }
}
