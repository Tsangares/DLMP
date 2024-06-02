#Image processing imports
from PIL import Image, ImageDraw, ImageFilter, ImageOps

#General imports
import json,random,os,io,math
import numpy as np

def send_png(img):
    img_io = io.BytesIO()
    img.save(img_io,'png')
    img_io.seek(0)
    return send_file(img_io,mimetype='image/png')

def get_convex_polygon(N,radius=10,theta=0,origin=(0,0)):
    points = []
    origin_X,origin_Y = origin
    for i in range(N+1):
        angle = i*2*math.pi/N - theta + math.pi/2
        p = (math.cos(angle)*radius + origin_X,
             math.sin(angle)*radius + origin_Y)
        points.append(p)
    return points


def square_wave(theta):
    return 1 if theta%(2*math.pi)>math.pi else 0

def sawtooth(theta):
    return 5*(theta%(2*math.pi))/(4*math.pi)
def rsawtooth(theta):
    return -sawtooth(theta)

def triangle(theta):
    if theta%(2*math.pi) >= math.pi:
        return (theta%math.pi)/4
    else:
        return (math.pi-theta%math.pi)/4
    
def get_wobble(density=30,depth=10,radius=10,theta=0,origin=(0,0),wave=1):
    if wave==1:
        wave = math.sin
    elif wave==3:
        wave = triangle
    elif wave==4:
        wave = square_wave
    elif wave==5:
        wave = sawtooth
    elif wave==6:
        wave = rsawtooth


    points = []
    origin_X,origin_Y = origin
    N=360
    for i in range(N+1):
        angle = i*2*math.pi/N - theta + math.pi/2
        r = radius + depth * wave(i*2*math.pi/density)
        p = (math.cos(angle)*r + origin_X,
             math.sin(angle)*r + origin_Y)
        points.append(p)
    return points


def rotate(origin, point, angle):
    ox, oy = origin
    px, py = point

    qx = ox + math.cos(angle) * (px - ox) - math.sin(angle) * (py - oy)
    qy = oy + math.sin(angle) * (px - ox) + math.cos(angle) * (py - oy)
    return qx, qy

def get_ribbon(center=(0,0),angle=0,depth=1,width=100,height=200):
    cx,cy=center
    cx -= width/2
    cy -= 0
    points = [
        (0,0),
        (0,height),
        (width/2,height*(3+depth)/5),
        (width,height),
        (width,0),
        (0,0)
    ]
    output = []
    for p in points:
        px,py = p
        nx,ny = rotate((cx+width/2,cy),(px+cx,py+cy),angle)
        output.append((nx,ny))
    return output

def draw_flower(draw,N,radius=10,width=1,origin=(0,0),color="#FFF"):
    centers = get_convex_polygon(N,radius,origin=origin)
    for c in centers+[origin]:
        box = [
            (c[0]-radius,c[1]-radius),
            (c[0]+radius,c[1]+radius),
        ]
        draw.ellipse(box,outline=color,width=width)
#("#0A0C1C","#242760","#2c3273","#515590","#FFF"),
colors = [
    ("#300303","#710808","#cc0f0f","#f8a5a5"), #Red
    ("#0A0C1C","#2c3273","#515590","#FFF"), #Blue
    ("#104E5D","#219EBC","#60C9E3","#CAEDF6"), #NP
]
def mk_badge():
    dark,mid,light,lightest = random.choice(colors)
    radius = 100
    ribbons = random.randint(0,3)
    laceType = random.choices([1,3,4,5,6],weights=[10,6,3,2,1],k=1)[0]
    ribbon_weight = (5-ribbons)/4
    polygonDegree = random.randint(3,8)
    stats = {
        'colors': colors,
        'radius': radius,
        'polygonDegree': polygonDegree,
        'laceType': laceType,
        'laceDepth': random.randint(2+laceType,8+laceType), #Depth of wave
        'laceDensity': random.randint(5+laceType*2,20), #Number of repetitions
        'laceRadius': random.randint(radius-5,radius+12), #Radius from center of polygon
        'ribbonDepth': random.random(),
        'ribbonQuantity': ribbons,
        'ribbonWidth': random.randint(int(50),int(75+25*ribbon_weight)),
        'ribbonHeight': random.randint(200,int(200 + 25*ribbon_weight)),
        'insigniaQuantity': random.randint(3,9),
        'insigniaRadius': random.randint(10,int(25+25*(polygonDegree-3)/5)),
        'insigniaWidth': random.randint(1,2),
    }
    
    size = 400
    center = (size/2,150)
    img = Image.new("RGBA",(size,size))
    draw = ImageDraw.Draw(img, "RGBA")
    star = get_convex_polygon(stats['polygonDegree'],radius,origin=center)
    wobble = get_wobble(stats['laceDensity'],stats['laceDepth'],stats['laceRadius'],origin=center,wave=stats['laceType'])
    
    for i in range(ribbons):
        if ribbons == 1:
            angle = 0
        else:
            angle = np.linspace(-math.pi/6,math.pi/6,ribbons)[i]
        ribbon = get_ribbon(center,angle=angle,depth=stats['ribbonDepth'],width=stats['ribbonWidth'],height=stats['ribbonHeight'])
        draw.polygon(ribbon,fill=dark)
    draw.polygon(wobble,fill=light)
    draw.polygon(star,fill=mid)
    
    draw_flower(draw,stats['insigniaQuantity'],stats['insigniaRadius'],stats['insigniaWidth'],center,color=lightest)

    return img,stats

def make_badge(seed):
    random.seed(seed)
    return mk_badge()
