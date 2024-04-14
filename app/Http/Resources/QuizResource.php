<?php

namespace App\Http\Resources;

use App\Types\UserType;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Facades\Auth;

class QuizResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $pivot = $this->pivot;
        $base = [
            'title' => $this->title,
            'description' => $this->description,
            'questions' => $request->user()->type === UserType::ADMIN ? QuestionResource::collection($this->forAdminQuestions) : QuestionResource::collection($this->forUserQuestions)
        ];
        if ($pivot){
            $base = array_merge($base , [
                'is_free' => $pivot->is_free
            ]);
        }
        return $base;
    }
}
