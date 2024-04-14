<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ShowCourseInformationForAdmin extends JsonResource
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
            'name' => $this->name,
            'image' => $this->image ? asset($this->image) : null,
            'telegram_channel_link' => $this->telegram_channel_link,
            'is_open' => boolval($this->is_open),
            'is_visible' => boolval($this->is_visible),
            'chapters' => ChapterInformationForAdmin::collection($this->chapters),
            'teachers' => $this->teachers,
            'categories' => $this->categories,
            'values' => $this->courseValues
        ];
    }
}
