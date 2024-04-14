<?php

namespace App\Http\Resources;

use App\Models\UserWatch;
use App\Types\UserType;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Facades\Storage;

class LesionResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $link = $this->link;

        $data = [
            'id' => intval($this->id),
            'title' => $this->title,
            'description' => $this->description,
            'link' => $this->type === 'pdf' ? asset('storage/'.$this->link) : $link,
            'time' => intval($this->time),
            'is_open' => boolval($this->is_open),
            'is_visible' => boolval($this->is_visible),
            'type' => $this->type,
            'is_watched' => UserWatch::where('lesion_id' , $this->id)->where('user_id' , $request->user()->id)->exists(),
            'chapter_id' => intval($this->chapter_id),
        ];
        if (strval($this->type) === 'video'){
            $data = array_merge($data , ['link_uri' => $link]);
        }
        return $data;
    }

}
