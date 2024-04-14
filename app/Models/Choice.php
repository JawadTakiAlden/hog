<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Choice extends Model
{
    use HasFactory;
    protected $guarded = ['id'];

    public function question(){
        return $this->belongsTo(Question::class);
    }

    public function setImageAttribute ($image){
        $newImageName = uniqid() . '_' . 'image' . '.' . $image->extension();
        $image->move(public_path('choice_images') , $newImageName);
        return $this->attributes['image'] =  '/'.'choice_images'.'/' . $newImageName;
    }
}
