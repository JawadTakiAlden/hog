<?php

namespace App\Http\Requests;

use App\Types\CodeType;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreActivationCodeRequest extends FormRequest
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
            'type' => 'required|string|in:'.implode(',',[CodeType::SINGLE ,CodeType::SHARED , CodeType::SHARED_SELECTED , CodeType::GIFt]),
            'quantity' => 'required|numeric|min:1|max:200',
            'title' => 'nullable|string|max:255',
            'number_of_courses' => 'required_if:type,' . CodeType::SHARED_SELECTED . '|numeric|min:1' ,
            'courses' => 'required_if:type,' . CodeType::SINGLE . '|required_if:type,' . CodeType::SHARED . '|array',
            'courses.*' => ['required' , 'numeric' , Rule::exists('courses' , 'id')],
        ];
    }
}
