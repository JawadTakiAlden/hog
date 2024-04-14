<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreQuestionRequest extends FormRequest
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
            'title' => 'required_without:image|string',
            'image' => 'required_without:title|image|mimes:jpg,png,jpeg',
            'clarification_text' => 'required_without:clarification_image|string',
            'clarification_image' => 'required_without:clarification_text|image|mimes:jpg,png,jpeg',
//            'choices' => 'required|array',
//            'choices.*.title' => 'required_without:choices.*.image|string',
//            'choices.*.image' => 'required_without:choices.*.title|image|mimes:jpg,png,jpeg',
//            'choices.*.is_true' => 'required|boolean',
        ];
    }
}
