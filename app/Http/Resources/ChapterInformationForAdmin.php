<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ChapterInformationForAdmin extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => intval($this->id),
            'name' => strval($this->name),
            'is_visible' => boolval($this->is_visible),
            'lesions' => LesionResource::collection($this->lesions),
            'quizzes' => SimpleQuizResource::collection($this->quizzes)
        ];
    }
}
