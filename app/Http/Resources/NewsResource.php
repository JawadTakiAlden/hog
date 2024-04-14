<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class NewsResource extends JsonResource
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
            'image' => $this->image ? asset($this->image) : null,
            'title' => $this->title,
            'position' => $this->position,
            'position_update' => $this->position_update,
            'is_visible' => boolval($this->is_visible)
        ];
    }
}
