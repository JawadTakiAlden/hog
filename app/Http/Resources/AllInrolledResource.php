<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class AllInrolledResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->user->full_name,
            'phone' => $this->user->phone,
            'course_title' => $this->course->name,
            'enrole_date' => $this->created_at->format('Y/m/d g:i A'),
            'code' => $this->activationCode,
        ];
    }
}
