<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class RecentEnrolledResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $user = $this->user;
        return [
            'course_title' => $this->course->name,
            'student_name' => $user->full_name,
            'phone' => $user->phone,
            'created_at' => $this->created_at->diffForHumans()
        ];
    }
}
