<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Lesion extends Model
{
    use HasFactory;
    protected $guarded = ['id'];

    public function chapter(){
        return $this->belongsTo(Chapter::class);
    }
}
